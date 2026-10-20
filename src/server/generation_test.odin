package server

import "core:fmt"
import "core:mem/virtual"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "elodin:cache"
import "elodin:config"
import "elodin:dns"
import "elodin:filter"

/*
A server booted from one configuration, reloadable from a file of its own.

What `main` does, minus the listeners: the first generation is built from a
configuration the fixture keeps, and every reload reads `path`.
*/
@(private = "file")
Gen_Fixture :: struct {
	s:     Server,
	arena: virtual.Arena,
	cfg:   config.Config,
	path:  string,
}

@(private = "file")
BASE :: `log: { level: info }
upstream: { servers: ["127.0.0.1:1"], timeout: 1s }
dnssec: { enabled: false }
blocking: { enabled: false }
cookies: { enabled: true }
server:
  rate_limit: { enabled: true, responses_per_second: 100 }
`

@(private = "file")
boot_fixture :: proc(t: ^testing.T, name: string, text: string) -> (f: ^Gen_Fixture, ok: bool) {
	f = new(Gen_Fixture)
	// Per process: other worktrees run this suite on the same box.
	f.path = fmt.aprintf("/tmp/elodin-server-generation-test-%s-%d.yaml", name, os.get_pid())
	if err := virtual.arena_init_growing(&f.arena); err != nil {
		testing.expectf(t, false, "cannot reserve an arena: %v", err)
		free(f)
		return nil, false
	}
	cfg, err := config.load_string(text, virtual.arena_allocator(&f.arena))
	if e, has := err.?; has {
		testing.expectf(t, false, "the boot configuration does not load: %v", e.messages)
		virtual.arena_destroy(&f.arena)
		free(f)
		return nil, false
	}
	f.cfg = cfg
	f.s.filters = filter.engine_make()
	if !boot_generation(&f.s, &f.cfg) {
		testing.expect(t, false, "the boot configuration could not be put into effect")
		filter.engine_destroy(f.s.filters)
		virtual.arena_destroy(&f.arena)
		free(f)
		return nil, false
	}
	return f, true
}

@(private = "file")
close_fixture :: proc(f: ^Gen_Fixture) {
	destroy_generations(&f.s)
	filter.engine_destroy(f.s.filters)
	delete(f.s.lists_loaded)
	virtual.arena_destroy(&f.arena)
	os.remove(f.path)
	delete(f.path)
	free(f)
}

// `text` with `old` replaced, in the temp arena.
@(private = "file")
swap :: proc(text, old, new: string) -> string {
	out, _ := strings.replace_all(text, old, new, context.temp_allocator)
	return out
}

@(private = "file")
reload_from :: proc(t: ^testing.T, f: ^Gen_Fixture, text: string) -> Reload_Outcome {
	testing.expect(t, os.write_entire_file(f.path, text) == nil, "cannot write the reloaded configuration")
	return reload_config(&f.s, f.path, false)
}

@(test)
test_a_reload_hands_unchanged_parts_to_the_new_generation :: proc(t: ^testing.T) {
	/*
	A rewrite edit touches nothing built from the other sections: the upstream
	connections and their cookies, the cached answers, the client cookie secret
	and the rate limiter's budgets are the ones already running, and the duty to
	release them moves with them.
	*/
	f, ok := boot_fixture(t, "carry", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current

	out := reload_from(t, f, BASE + "rewrites:\n  - { domain: carried.test, answer: 192.0.2.1 }\n")
	testing.expect(t, out.applied, "the reload was not applied")
	cur := f.s.gens.current
	if !testing.expect(t, cur != old, "no new generation") {
		return
	}
	testing.expect(t, cur.group == old.group, "an unchanged upstream section rebuilt the group")
	testing.expect(t, cur.answers == old.answers, "an unchanged cache section rebuilt the cache")
	testing.expect(t, cur.cookies == old.cookies, "an unchanged cookie section rebuilt the keeper")
	testing.expect(t, cur.limiter == old.limiter, "an unchanged rate limit rebuilt the limiter")
	testing.expect_value(t, cur.policy, old.policy)
	testing.expect_value(t, cur.owns, Parts{.Upstreams, .Cookies, .Limiter, .Answers})
	testing.expect_value(t, old.owns, Parts{})
	testing.expect_value(t, len(cur.cfg.rewrites), 1)
}

@(test)
test_a_reload_that_changes_the_upstreams_rebuilds_them_and_moves_the_policy :: proc(t: ^testing.T) {
	/*
	An answer from an upstream the file no longer names is not what the new
	configuration would have asked for, so the cache is emptied and every key
	moves to a new policy number - which is also what keeps an answer a request
	still running under the old configuration stores after the reload from being
	served under the new one.
	*/
	f, ok := boot_fixture(t, "upstreams", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current

	msg := dns.Message {
		id       = 1,
		question = []dns.Question{{name = "cached.test.", type = .A, class = .IN}},
		answer   = []dns.Record{{name = "cached.test.", type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, 9}}}},
	}
	msg.flags.qr = true
	wire, _, enc := dns.encode_message(msg, context.temp_allocator)
	testing.expect_value(t, enc, dns.Encode_Error.None)
	old_buf: [cache.KEY_MAX]u8
	old_key := cache.make_key(old_buf[:], "cached.test.", .A, .IN, false, policy = old.policy)
	testing.expect(t, cache.put(old.answers, old_key, wire, msg), "the answer was not stored")

	out := reload_from(
		t,
		f,
		`log: { level: info }
upstream: { servers: ["127.0.0.1:2"], timeout: 1s }
dnssec: { enabled: false }
blocking: { enabled: false }
cookies: { enabled: true }
server:
  rate_limit: { enabled: true, responses_per_second: 100 }
`,
	)
	testing.expect(t, out.applied, "the reload was not applied")
	cur := f.s.gens.current
	testing.expect(t, cur.group != old.group, "a changed upstream section kept the old group")
	testing.expect(t, cur.answers == old.answers, "the cache itself is kept")
	testing.expect(t, cur.policy != old.policy, "the policy number did not move")
	testing.expect_value(t, cache.len_entries(cur.answers), 0)

	// A request still under the old rules stores its answer after the reload.
	testing.expect(t, cache.put(cur.answers, old_key, wire, msg), "the late answer was not stored")
	new_buf: [cache.KEY_MAX]u8
	new_key := cache.make_key(new_buf[:], "cached.test.", .A, .IN, false, policy = cur.policy)
	_, _, found := cache.get(cur.answers, new_key, context.temp_allocator)
	testing.expect(t, !found, "an answer stored under the old rules was served under the new ones")
}

@(test)
test_a_reload_moves_the_policy_for_rebind_and_dnssec_but_not_rewrites :: proc(t: ^testing.T) {
	f, ok := boot_fixture(t, "policy", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)

	before := f.s.gens.current.policy
	reload_from(t, f, BASE + "rewrites:\n  - { domain: r.test, answer: 192.0.2.1 }\n")
	testing.expect_value(t, f.s.gens.current.policy, before)

	// Waiting on the same servers longer changes no answer they give.
	group := f.s.gens.current.group
	reload_from(t, f, swap(BASE, "timeout: 1s", "timeout: 2s"))
	testing.expect(t, f.s.gens.current.group != group, "a changed timeout was not applied")
	testing.expect_value(t, f.s.gens.current.policy, before)
	testing.expect(t, reload_from(t, f, swap(BASE, "timeout: 1s", "timeout: 2s, bootstrap: [\"127.0.0.9\"]")).applied, "the bootstrap change did not load")
	testing.expect(t, f.s.gens.current.policy != before, "a changed bootstrap left the answers it might have changed")
	before = f.s.gens.current.policy

	reload_from(t, f, BASE + "rebind: { enabled: true }\n")
	after_rebind := f.s.gens.current.policy
	testing.expect(t, after_rebind != before, "turning rebind protection on left cached answers it never read")

	reload_from(t, f, swap(BASE, "dnssec: { enabled: false }", "dnssec: { enabled: true }"))
	cur := f.s.gens.current
	testing.expect(t, cur.policy != after_rebind, "turning validation on left unvalidated answers cached")
	testing.expect(t, cur.validator != nil, "turning validation on built no validator")
	testing.expect(t, .Validator in cur.owns, "the new validator is nobody's to release")

	// Nor does the name a server is logged under.
	named :: proc(name: string) -> string {
		return swap(BASE, "servers: [\"127.0.0.1:1\"]", fmt.tprintf("servers: [{{ name: %s, address: 127.0.0.1, port: 1 }}]", name))
	}
	testing.expect(t, reload_from(t, f, named("one")).applied, "the named server did not load")
	before = f.s.gens.current.policy
	testing.expect(t, reload_from(t, f, named("two")).applied, "the rename did not load")
	testing.expect_value(t, f.s.gens.current.policy, before)
}

@(test)
test_a_reload_keeps_the_cookie_secret_unless_the_file_changes_it :: proc(t: ^testing.T) {
	/*
	A drawn secret is what every client holds its cookie under; a reload that
	only changes `require` must not draw another, or each client pays a round
	trip for an edit that had nothing to do with it.
	*/
	f, ok := boot_fixture(t, "cookies", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current.cookies
	secret := old.secret

	reload_from(t, f, swap(BASE, "cookies: { enabled: true }", "cookies: { enabled: true, require: true }"))
	cur := f.s.gens.current.cookies
	if !testing.expect(t, cur != nil, "no keeper after the reload") {
		return
	}
	testing.expect(t, cur.require, "require was not applied")
	testing.expect(t, cur.secret == secret, "a reload that left the secret alone drew a new one")

	reload_from(
		t,
		f,
		swap(
			BASE,
			"cookies: { enabled: true }",
			"cookies: { enabled: true, secret: \"000102030405060708090a0b0c0d0e0f\" }"),
	)
	testing.expect(t, f.s.gens.current.cookies.secret != secret, "a configured secret did not replace the drawn one")
}

@(test)
test_a_reload_of_an_unusable_file_keeps_the_running_configuration :: proc(t: ^testing.T) {
	f, ok := boot_fixture(t, "unusable", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current

	out := reload_from(t, f, "upstream: { servers: [\n")
	testing.expect(t, !out.applied, "an unparseable file was applied")
	testing.expect(t, f.s.gens.current == old, "an unparseable file replaced the running generation")

	// Parses, and is refused by the loader's own checks: a cookie secret that is
	// not hex. A file that loads and then cannot be built is
	// `test_a_reload_that_cannot_be_built_releases_what_it_built`.
	out = reload_from(
		t,
		f,
		swap(
			BASE,
			"cookies: { enabled: true }",
			"cookies: { enabled: true, secret: \"not hex at all, not hex at all!\" }"),
	)
	testing.expect(t, !out.applied, "a configuration that could not be built was applied")
	testing.expect(t, f.s.gens.current == old, "a half-built configuration replaced the running one")
	testing.expect(t, f.s.gens.retired == nil, "a refused reload retired the running generation")
}

@(test)
test_a_reload_holds_restart_only_keys_at_their_starting_values :: proc(t: ^testing.T) {
	f, ok := boot_fixture(t, "restart", BASE + "listeners: { udp: { port: 5300 } }\n")
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current
	workers := old.cfg.server.workers

	// Only keys that need a restart: nothing a reload can apply has changed.
	out := reload_from(
		t,
		f,
		strings.concatenate(
			{swap(BASE, "server:\n", fmt.tprintf("server:\n  workers: %d\n", workers + 3)), "listeners: { udp: { port: 5301 } }\n"},
			context.temp_allocator,
		),
	)
	testing.expect(t, !out.applied, "a change to restart-only keys alone made a new generation")
	testing.expect(t, f.s.gens.current == old, "the running generation was replaced")

	// With something else beside them, the rest is applied and they are held.
	out = reload_from(
		t,
		f,
		strings.concatenate(
			{
				swap(BASE, "blocking: { enabled: false }", "blocking: { enabled: false, cache_dir: /var/tmp/elsewhere }"),
				"listeners: { udp: { port: 5301 } }\nrewrites:\n  - { domain: h.test, answer: 192.0.2.1 }\n",
			},
			context.temp_allocator,
		),
	)
	testing.expect(t, out.applied, "the reloadable part was not applied")
	testing.expect_value(t, f.s.gens.current.cfg.listeners.udp.port, 5300)
	testing.expect_value(t, f.s.gens.current.cfg.blocking.cache_dir, old.cfg.blocking.cache_dir)
	testing.expect_value(t, f.s.gens.current.cfg.server.workers, workers)
	testing.expect_value(t, len(f.s.gens.current.cfg.rewrites), 1)
}

@(private = "file")
Holder :: struct {
	s:        ^Server,
	pinned:   sync.Sema,
	release:  sync.Sema,
	// What the holder read through `live` after both reloads had landed.
	saw:      ^config.Config,
	saw_late: sync.Sema,
	go_read:  sync.Sema,
}

@(private = "file")
hold_a_request :: proc(h: ^Holder) {
	pin(h.s)
	sync.sema_post(&h.pinned)
	sync.sema_wait(&h.go_read)
	h.saw = live(h.s).cfg
	sync.sema_post(&h.saw_late)
	sync.sema_wait(&h.release)
	unpin(h.s)
}

@(test)
test_a_retired_generation_waits_for_its_requests_and_goes_oldest_first :: proc(t: ^testing.T) {
	/*
	A request pinned before two reloads keeps reading the configuration it
	started under, and holds back not only that generation but the one after it,
	which may own something the first is still reading. Once it lets go both go,
	oldest first.
	*/
	f, ok := boot_fixture(t, "reap", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	first := f.s.gens.current

	h := Holder {
		s = &f.s,
	}
	holder := thread.create_and_start_with_poly_data(&h, hold_a_request)
	sync.sema_wait(&h.pinned)

	reload_from(t, f, BASE + "rewrites:\n  - { domain: one.test, answer: 192.0.2.1 }\n")
	reload_from(t, f, swap(BASE, "127.0.0.1:1", "127.0.0.1:2"))
	testing.expect(t, f.s.gens.current != first, "no reload landed")

	sync.sema_post(&h.go_read)
	sync.sema_wait(&h.saw_late)
	testing.expect(t, h.saw == first.cfg, "a pinned request moved to a newer configuration mid-flight")

	testing.expect_value(t, reap_generations(&f.s), 0)
	testing.expect(t, f.s.gens.retired == first, "the oldest retired generation is not at the head")

	sync.sema_post(&h.release)
	thread.join(holder)
	thread.destroy(holder)
	testing.expect_value(t, reap_generations(&f.s), 2)
	testing.expect(t, f.s.gens.retired == nil, "a released generation is still listed")
}

@(test)
test_reload_change_detection_reads_every_section :: proc(t: ^testing.T) {
	/*
	The premise every carry-over decision rests on: `differs` reads a whole
	section, slices and nested structs included, and the same file loaded twice
	reads as unchanged. A comparison that missed a field would keep a part built
	from the old value; one that saw a difference in identical text would rebuild
	everything on every SIGHUP.
	*/
	TEXT :: `upstream:
  servers: ["127.0.0.1:1", "tls://127.0.0.1:853#dns.example"]
  zones:
    - { domains: [corp.example], servers: ["10.0.0.1"] }
server:
  allow_from: [10.0.0.0/8, 192.168.0.0/16]
  rate_limit:
    enabled: true
    overrides: [{ prefix: 10.0.0.0/8, responses_per_second: 1000 }]
rewrites:
  - { domain: a.test, answer: 192.0.2.1 }
  - { domain: mx.test, answer: "MX 10 mail.test" }
rebind: { enabled: true, allow_domains: [lan.example] }
blocking:
  rules: ["||ads.example^"]
dnssec:
  trust_anchors: [". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
`
	arena: virtual.Arena
	testing.expect(t, virtual.arena_init_growing(&arena) == nil)
	defer virtual.arena_destroy(&arena)
	a, aerr := config.load_string(TEXT, virtual.arena_allocator(&arena))
	b, berr := config.load_string(TEXT, virtual.arena_allocator(&arena))
	if ea, has := aerr.?; has {
		testing.expectf(t, false, "%v", ea.messages)
		return
	}
	if eb, has := berr.?; has {
		testing.expectf(t, false, "%v", eb.messages)
		return
	}
	testing.expect_value(t, changed_sections(&a, &b, context.temp_allocator), "")

	b.rewrites[1].answers[0].preference = 20
	testing.expect_value(t, changed_sections(&a, &b, context.temp_allocator), "rewrites")
	b.rewrites[1].answers[0].preference = a.rewrites[1].answers[0].preference

	b.upstream.zones[0].upstream.servers[0].port = 54
	testing.expect_value(t, changed_sections(&a, &b, context.temp_allocator), "upstream")
	b.upstream.zones[0].upstream.servers[0].port = a.upstream.zones[0].upstream.servers[0].port

	b.server.rate_limit.overrides[0].responses_per_second = 1
	testing.expect_value(t, changed_sections(&a, &b, context.temp_allocator), "server")
	b.server.rate_limit.overrides[0].responses_per_second = a.server.rate_limit.overrides[0].responses_per_second

	b.server.allow_from[1].bits = 24
	testing.expect_value(t, changed_sections(&a, &b, context.temp_allocator), "server")
	b.server.allow_from[1].bits = a.server.allow_from[1].bits

	b.dnssec.trust_anchors = []string{strings.concatenate({a.dnssec.trust_anchors[0], " "}, context.temp_allocator)}
	testing.expect_value(t, changed_sections(&a, &b, context.temp_allocator), "dnssec")
	b.dnssec.trust_anchors = a.dnssec.trust_anchors

	b.rebind.allow_domains = []string{"other.example"}
	b.blocking.rules = []string{"||ads.example^", "||more.example^"}
	testing.expect_value(t, changed_sections(&a, &b, context.temp_allocator), "blocking,rebind")
}

@(test)
test_a_lists_history_follows_it_to_its_new_position :: proc(t: ^testing.T) {
	/*
	`reload_filters` keeps the rules in effect when a list that loaded before is
	unavailable now, and reads "loaded before" by position. A list added ahead
	of it moves that position, so the history has to move with the list - and a
	list that is new has none.
	*/
	old := config.default_config()
	old.blocking.lists = []config.Block_List{{url = "http://a.example/l"}, {url = "http://b.example/l"}}
	old.blocking.allow_lists = []config.Block_List{{file = "/etc/allow"}}
	cfg := config.default_config()
	cfg.blocking.lists = []config.Block_List{{url = "http://new.example/l"}, {url = "http://b.example/l"}, {url = "http://a.example/l"}}
	cfg.blocking.allow_lists = []config.Block_List{{file = "/etc/allow"}}

	s: Server
	s.lists_loaded = make([]bool, 3)
	s.lists_loaded[0] = true
	s.lists_loaded[1] = false
	s.lists_loaded[2] = true
	defer delete(s.lists_loaded)

	remap_lists_loaded(&s, &old, &cfg)
	if !testing.expect_value(t, len(s.lists_loaded), 4) {
		return
	}
	testing.expect_value(t, s.lists_loaded[0], false)
	testing.expect_value(t, s.lists_loaded[1], false)
	testing.expect_value(t, s.lists_loaded[2], true)
	testing.expect_value(t, s.lists_loaded[3], true)
}

@(test)
test_a_reload_rebuilds_the_rules_and_takes_them_away_with_blocking :: proc(t: ^testing.T) {
	blocking :: proc(rules: string) -> string {
		return swap(
			BASE,
			"blocking: { enabled: false }",
			fmt.tprintf("blocking: {{ enabled: true, cache_dir: /nonexistent/elodin-test, rules: [%s] }}", rules),
		)
	}
	f, ok := boot_fixture(t, "rules", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)

	out := reload_from(t, f, blocking(`"||first.example^"`))
	testing.expect(t, out.applied && out.blocking, "turning blocking on was not a blocking change")
	testing.expect_value(t, filter.engine_match(f.s.filters, "first.example", .A), filter.Decision.Blocked)

	reload_from(t, f, blocking(`"||second.example^"`))
	testing.expect_value(t, filter.engine_match(f.s.filters, "second.example", .A), filter.Decision.Blocked)
	testing.expect(t, filter.engine_match(f.s.filters, "first.example", .A) != .Blocked, "a removed rule still blocks")

	reload_from(t, f, BASE)
	testing.expect(t, filter.engine_match(f.s.filters, "second.example", .A) != .Blocked, "turning blocking off left the rules in the engine")
}

@(test)
test_an_answer_stored_under_a_replaced_policy_is_not_served :: proc(t: ^testing.T) {
	/*
	The race the policy number closes, through the resolver rather than the cache
	alone: a request that started before a reload turning rebind protection on
	stores its private answer after the reload has emptied the cache. The next
	query, under the new generation, must not be answered from it. The control
	is the same answer stored under the new number, which is served.
	*/
	f, ok := boot_fixture(t, "late-store", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current.policy
	if !testing.expect(t, reload_from(t, f, BASE + "rebind: { enabled: true }\n").applied, "the reload was not applied") {
		return
	}
	cur := f.s.gens.current

	store :: proc(t: ^testing.T, c: ^cache.Cache, name: string, policy: u64) {
		msg := dns.Message {
			id       = 1,
			question = []dns.Question{{name = name, type = .A, class = .IN}},
			answer   = []dns.Record{{name = name, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {198, 51, 100, 1}}}},
		}
		msg.flags.qr = true
		msg.flags.rd = true
		msg.flags.ra = true
		wire, _, _ := dns.encode_message(msg, context.temp_allocator)
		buf: [cache.KEY_MAX]u8
		key := cache.make_key(buf[:], name, .A, .IN, false, policy = policy)
		testing.expect(t, cache.put(c, key, wire, msg), "the answer was not stored")
	}
	served :: proc(t: ^testing.T, s: ^Server, name: string) -> int {
		q := dns.Message {
			id       = 7,
			question = []dns.Question{{name = name, type = .A, class = .IN}},
		}
		q.flags.rd = true
		wire, _, _ := dns.encode_message(q, context.temp_allocator)
		out, _, ok := handle_query(s, wire, .UDP, "127.0.0.1:5555", context.temp_allocator)
		if !ok {
			return -1
		}
		msg, err := dns.decode_message(out, context.temp_allocator)
		if err != .None {
			return -1
		}
		return len(msg.answer)
	}

	store(t, cur.answers, "late.example.", old)
	testing.expect_value(t, served(t, &f.s, "late.example."), 0)
	store(t, cur.answers, "current.example.", cur.policy)
	testing.expect_value(t, served(t, &f.s, "current.example."), 1)
}

@(test)
test_a_retired_group_is_kept_while_a_race_worker_still_asks_it :: proc(t: ^testing.T) {
	/*
	A race worker outlives the request that started it, so a generation nothing
	has pinned can still have one of its upstreams in use; releasing it then
	would free the upstream under the worker.
	*/
	f, ok := boot_fixture(t, "racing", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current
	reload_from(t, f, swap(BASE, "127.0.0.1:1", "127.0.0.1:2"))
	if !testing.expect(t, f.s.gens.retired == old, "the upstream change did not retire the generation") {
		return
	}

	sync.atomic_add(&old.group.racing, 1)
	testing.expect_value(t, reap_generations(&f.s), 0)
	sync.atomic_sub(&old.group.racing, 1)
	testing.expect_value(t, reap_generations(&f.s), 1)
}

@(test)
test_a_reload_that_cannot_be_built_releases_what_it_built :: proc(t: ^testing.T) {
	/*
	A file that loads and then cannot be put into effect - a root anchor naming
	an algorithm no build can check, found only when the validator is built,
	after the new upstreams already are - leaves the running generation alone and
	nothing of the attempt behind. The test runner's allocator is what notices
	the second half.
	*/
	f, ok := boot_fixture(t, "unbuildable", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)
	old := f.s.gens.current

	broken := swap(
		swap(BASE, "127.0.0.1:1", "127.0.0.1:2"),
		"dnssec: { enabled: false }",
		"dnssec: { enabled: true, trust_anchors: [\". IN DS 20326 1 1 0000000000000000000000000000000000000000\"] }",
	)
	out := reload_from(t, f, broken)
	testing.expect(t, !out.applied, "a configuration whose validator could not be built was applied")
	testing.expect(t, f.s.gens.current == old, "the running generation was replaced")
	testing.expect(t, f.s.gens.retired == nil, "the running generation was retired")
}

@(test)
test_a_reload_that_adds_a_list_keeps_each_lists_history :: proc(t: ^testing.T) {
	/*
	Through `reload_config`, so it is the reload that moves the history: a list
	inserted ahead of one that loaded before shifts it a position, and the one
	that loaded before is then unavailable. Its rules stay in effect, which is
	what `reload_filters` does for a list it has a record of loading.
	*/
	dir := fmt.tprintf("/tmp/elodin-server-generation-test-lists-%d", os.get_pid())
	_ = os.make_directory(dir)
	defer os.remove(dir)
	LISTS :: `blocking: {{ enabled: true, cache_dir: %q, lists: [%s] }}`
	a_list := `{ name: a, url: "http://127.0.0.1:1/a.txt" }`
	b_list := `{ name: b, url: "http://127.0.0.1:1/b.txt" }`
	first := swap(BASE, "blocking: { enabled: false }", fmt.tprintf(LISTS, dir, a_list))
	f, ok := boot_fixture(t, "lists", first)
	if !ok {
		return
	}
	defer close_fixture(f)

	a_path := strings.clone(list_cache_path(f.s.gens.current.cfg, f.s.gens.current.cfg.blocking.lists[0]))
	defer delete(a_path)
	testing.expect(t, os.write_entire_file(a_path, "||a.example^\n") == nil)
	defer os.remove(a_path)
	pin(&f.s)
	reload_filters(&f.s, false)
	unpin(&f.s)
	testing.expect_value(t, filter.engine_match(f.s.filters, "a.example", .A), filter.Decision.Blocked)

	os.remove(a_path)
	both := swap(BASE, "blocking: { enabled: false }", fmt.tprintf(LISTS, dir, fmt.tprintf("%s, %s", b_list, a_list)))
	// The new list is there to be loaded; the old one, now second, is not.
	b_path := fmt.tprintf("%s/%s", dir, config.list_cache_file(config.Block_List{name = "b", url = "http://127.0.0.1:1/b.txt"}))
	testing.expect(t, os.write_entire_file(b_path, "||b.example^\n") == nil)
	defer os.remove(b_path)
	out := reload_from(t, f, both)
	testing.expect(t, out.applied && out.blocking, "adding a list was not a blocking change")
	testing.expect(t, !out.lists_current, "a list that loaded before and is unavailable now reads as current")
	testing.expect_value(t, filter.engine_match(f.s.filters, "a.example", .A), filter.Decision.Blocked)
	testing.expect(t, filter.engine_match(f.s.filters, "b.example", .A) != .Blocked, "the rules in effect were not the ones kept")
}

@(test)
test_upstreams_handed_on_outlive_the_configuration_that_built_them :: proc(t: ^testing.T) {
	/*
	A group a reload built is handed to the next reload's generation, and the one
	that built it is then released with its whole configuration. What the group
	reads of that configuration - an upstream's address, a route's domains - has
	to be its own by then.
	*/
	ROUTED :: `log: { level: info }
upstream:
  servers: ["127.0.0.1:2"]
  timeout: 1s
  zones: [{ domains: [corp.example], servers: ["127.0.0.1:3"] }]
dnssec: { enabled: false }
blocking: { enabled: false }
`
	f, ok := boot_fixture(t, "outlive", BASE)
	if !ok {
		return
	}
	defer close_fixture(f)

	reload_from(t, f, ROUTED)
	built := f.s.gens.current
	reload_from(t, f, ROUTED + "rewrites:\n  - { domain: o.test, answer: 192.0.2.1 }\n")
	cur := f.s.gens.current
	if !testing.expect(t, cur != built && cur.group == built.group, "the group was not handed on") {
		return
	}
	testing.expect_value(t, reap_generations(&f.s), 2)

	testing.expect_value(t, cur.group.servers[0].spec.address, "127.0.0.1")
	if testing.expect_value(t, len(cur.routes), 1) {
		testing.expect_value(t, cur.routes[0].domains[0], "corp.example.")
		testing.expect_value(t, cur.routes[0].group.servers[0].spec.address, "127.0.0.1")
	}
}
