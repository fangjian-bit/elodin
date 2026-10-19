package server

import "core:mem/virtual"
import "core:reflect"
import "core:strings"
import "elodin:cache"
import "elodin:config"
import "elodin:filter"
import "elodin:logx"

/*
What a configuration reload did, for the caller's bookkeeping.
*/
Reload_Outcome :: struct {
	// A new configuration is in effect.
	applied:       bool,
	// Its blocking section changed, so the rule sets were rebuilt.
	blocking:      bool,
	// Whether every list the rebuilt rule sets wanted was current; see
	// `reload_filters`. True when nothing was rebuilt.
	lists_current: bool,
}

/*
Read the configuration file again and put into effect what it changes.

Everything is validated and built before anything is swapped: the file goes
through the loader `--check` runs, and every part a change needs - upstream
groups, the validator and its anchors, the cookie secret - is built before the
generation is swapped in. A file that fails any of that leaves the running
configuration exactly as it was and says why. A reload that half-applies would
be worse than one that does not happen: the operator would be running a
configuration nobody wrote.

The keys that need a restart are named in a warning and held at the value the
process started with, and everything else in the file is applied: refusing a
whole reload over a listener address would leave an operator choosing between
their rewrites and a restart they did not want yet. See `keep_restart_only`.

Runs on the maintenance thread, which is the only one that swaps or releases a
generation, and must not be called with a generation pinned.
*/
reload_config :: proc(s: ^Server, path: string, allow_network: bool) -> (out: Reload_Outcome) {
	assert(pinned.server == nil, "reload_config runs with no generation pinned")
	out.lists_current = true
	cur := s.gens.current

	arena := new(virtual.Arena)
	if err := virtual.arena_init_growing(arena); err != nil {
		free(arena)
		logx.errorf("reload: cannot reserve memory for the configuration (%v); keeping the configuration already in effect", err)
		return
	}
	g := new(Generation)
	g.arena = arena
	keep := false
	defer if !keep {
		destroy_generation(g)
	}

	loaded, load_err := config.load_file(path, virtual.arena_allocator(arena))
	if e, has := load_err.?; has {
		for msg in e.messages {
			logx.errorf("reload: %s: %s", path, msg)
		}
		logx.warnf("reload: %s is not usable; keeping the configuration already in effect", path)
		return
	}
	g.config = loaded
	g.cfg = &g.config

	for key in keep_restart_only(s.gens.boot, g.cfg, context.temp_allocator) {
		logx.warnf("reload: %s changed, which takes a restart; it keeps the value the process started with until then", key)
	}
	if !differs(cur.cfg^, g.config) {
		logx.infof("reload: nothing a reload puts into effect has changed")
		return
	}

	built, ok := build_live(s, &g.live, &cur.live)
	if !ok {
		logx.warnf("reload: %s could not be put into effect; keeping the configuration already in effect", path)
		return
	}
	g.owns = built

	carried := Parts{.Upstreams, .Validator, .Cookies, .Limiter, .Answers} - built
	if g.validator == nil {
		carried -= {.Validator}
	}
	if g.cookies == nil {
		carried -= {.Cookies}
	}
	if g.limiter == nil {
		carried -= {.Limiter}
	}
	if g.answers == nil {
		carried -= {.Answers}
	}

	// The cache is shared with the generation it came from, so it is brought in
	// line only now that nothing can fail.
	answers := "off"
	if g.answers != nil {
		answers = "new" if .Answers in built else "kept"
		if .Answers in carried && differs(cur.cfg.cache, g.cfg.cache) {
			cache.reconfigure(g.answers, cache_options(g.cfg.cache))
		}
		if .Answers in carried && g.policy != cur.policy {
			cache.clear_all(g.answers)
			answers = "flushed"
		}
	}

	changed := changed_sections(cur.cfg, g.cfg, context.temp_allocator)
	out.blocking = differs(cur.cfg.blocking, g.cfg.blocking)
	if out.blocking {
		remap_lists_loaded(s, cur.cfg, g.cfg)
	}
	log_file_moved := g.cfg.log.file != cur.cfg.log.file

	swap_generation(s, g, carried)
	keep = true
	out.applied = true

	logx.set_level(logx.Level(g.cfg.log.level))
	if log_file_moved && !logx.reopen(g.cfg.log.file) {
		logx.warnf("reload: cannot open the log file %q; logging where it was", g.cfg.log.file)
	}

	if out.blocking {
		pin(s)
		if g.cfg.blocking.enabled {
			out.lists_current = reload_filters(s, allow_network)
		} else {
			clear_filters(s)
		}
		unpin(s)
	}

	rebuilt := parts_text(built, context.temp_allocator)
	if out.blocking {
		rebuilt = "rules" if built == {} else strings.concatenate({rebuilt, ",rules"}, context.temp_allocator)
	}
	logx.eventf(.Info, "reloaded", "changed=%s rebuilt=%s cache=%s", logx.quote(changed), logx.quote(rebuilt), answers)
	return
}

/*
Hold every key that needs a restart at the value the process started with, and
name the ones the file changed.

The listeners and the metrics endpoint, because their sockets were bound before
privileges were dropped: a port below 1024 cannot be bound again, and the worker
threads that serve them are started once. The pool sizes and the connection
table, because pools are not resized in place, and the DNSSEC chain-walk bounds
derived from them would otherwise describe pools that do not exist. And the
account, because root, once given up, cannot be had back. The certificates under
`listeners.dot` and `listeners.doh` are still read again on every SIGHUP, from
the paths the process started with.

Held at the starting value rather than at the previous reload's, which is the
same value for every key here - none of them has ever changed while running -
and is the one whose strings live as long as the process.
*/
@(private)
keep_restart_only :: proc(boot, cfg: ^config.Config, allocator := context.allocator) -> []string {
	changed := make([dynamic]string, allocator)
	hold(&changed, "listeners.udp", boot.listeners.udp, &cfg.listeners.udp)
	hold(&changed, "listeners.tcp", boot.listeners.tcp, &cfg.listeners.tcp)
	hold(&changed, "listeners.dot", boot.listeners.dot, &cfg.listeners.dot)
	hold(&changed, "listeners.doh", boot.listeners.doh, &cfg.listeners.doh)
	hold(&changed, "metrics", boot.metrics, &cfg.metrics)
	hold(&changed, "server.workers", boot.server.workers, &cfg.server.workers)
	// Named only where the file wrote them: one derived from `workers` moves
	// when `workers` does, and that is already the key to name.
	hold(
		&changed,
		"server.upstream_workers",
		boot.server.upstream_workers,
		&cfg.server.upstream_workers,
		cfg.server.sizing.derived_upstream_workers,
	)
	hold(
		&changed,
		"server.running_workers",
		boot.server.running_workers,
		&cfg.server.running_workers,
		cfg.server.sizing.derived_running_workers,
	)
	hold(&changed, "server.max_connections", boot.server.max_connections, &cfg.server.max_connections)
	hold(
		&changed,
		"server.max_connections_per_prefix",
		boot.server.max_connections_per_prefix,
		&cfg.server.max_connections_per_prefix,
	)
	hold(&changed, "server.user", boot.server.user, &cfg.server.user)
	hold(&changed, "server.group", boot.server.group, &cfg.server.group)

	/*
	What the loader derives from those keys where the file leaves a figure unset
	is derived again from the values that are running: a backlog of eight per
	worker, or a chain-walk bound that reserves a quarter of the pool, is only
	what it says it is when it is a share of the pool that exists. Where the file
	names the figure, it is the operator's and it reloads.

	The record of what was derived is the starting one for the keys held above,
	and the new file's for the figures derived here.
	*/
	derived := cfg.server.sizing
	cfg.server.sizing = boot.server.sizing
	cfg.server.sizing.derived_chain_walks = derived.derived_chain_walks
	cfg.server.sizing.derived_connection_walks = derived.derived_connection_walks
	cfg.server.sizing.derived_max_pending = derived.derived_max_pending
	if derived.derived_chain_walks {
		cfg.dnssec.max_chain_walks = config.derive_chain_walks(cfg.server.workers)
	}
	if derived.derived_connection_walks {
		cfg.dnssec.max_connection_walks = config.derive_chain_walks(cfg.server.max_connections)
	}
	if derived.derived_max_pending {
		cfg.server.max_pending = config.derive_max_pending(cfg.server.workers)
	}
	return changed[:]
}

@(private)
hold :: proc(changed: ^[dynamic]string, name: string, running: $T, loaded: ^T, derived := false) {
	if differs(running, loaded^) {
		if !derived {
			append(changed, name)
		}
		loaded^ = running
	}
}

/*
The top-level sections that differ, by the name they have in the file.

Read off the type rather than listed, so a section added later is reported
without anybody remembering to add it here.
*/
@(private)
changed_sections :: proc(a, b: ^config.Config, allocator := context.allocator) -> string {
	names := make([dynamic]string, context.temp_allocator)
	for field in reflect.struct_fields_zipped(config.Config) {
		x := reflect.struct_field_value(a^, field)
		y := reflect.struct_field_value(b^, field)
		if !reflect.equal(x, y, including_indirect_array_recursion = true) {
			append(&names, field.name)
		}
	}
	return strings.join(names[:], ",", allocator)
}

@(private)
parts_text :: proc(parts: Parts, allocator := context.allocator) -> string {
	names := make([dynamic]string, context.temp_allocator)
	for part in Part {
		if part in parts {
			name, _ := reflect.enum_name_from_value(part)
			append(&names, strings.to_lower(name, context.temp_allocator))
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.join(names[:], ",", allocator)
}

/*
Carry each list's "loaded before" over to where it sits in the new
configuration.

`lists_loaded` is indexed by position, and a reload that adds or removes a list
moves every position after it. A list is the same list if it is fetched from
the same place, and only such a list keeps its history; a new one starts with
none, which is what it would have at startup.
*/
@(private)
remap_lists_loaded :: proc(s: ^Server, old, cfg: ^config.Config) {
	if s.lists_loaded == nil {
		return
	}
	fresh := make([]bool, len(cfg.blocking.lists) + len(cfg.blocking.allow_lists))
	remap_kind(fresh[:len(cfg.blocking.lists)], cfg.blocking.lists, old.blocking.lists, s.lists_loaded[:len(old.blocking.lists)])
	remap_kind(
		fresh[len(cfg.blocking.lists):],
		cfg.blocking.allow_lists,
		old.blocking.allow_lists,
		s.lists_loaded[len(old.blocking.lists):],
	)
	delete(s.lists_loaded)
	s.lists_loaded = fresh
}

@(private)
remap_kind :: proc(fresh: []bool, lists, old: []config.Block_List, was: []bool) {
	for list, i in lists {
		for o, j in old {
			if o.url == list.url && o.file == list.file {
				fresh[i] = was[j]
				break
			}
		}
	}
}

/*
Take every rule out of effect, for a reload that turns blocking off.

What is checked per query is `blocking.enabled`, so this is about the memory:
the sets would otherwise sit there unread until the process ended.
*/
@(private)
clear_filters :: proc(s: ^Server) {
	old_block, old_allow := filter.engine_swap(s.filters, nil, nil)
	filter.set_destroy(old_block)
	filter.set_destroy(old_allow)
	delete(s.lists_loaded)
	s.lists_loaded = nil
}
