package itest

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:strings"
import "core:time"

/*
A blocklist rebuild hands the replaced rule sets' memory back (#513).

A rebuild allocates the new sets' tables, tens of MB at a few hundred thousand
rules, and frees the ones they replace. glibc serves blocks that large with
mmap and unmaps them on free, but each such free raises its dynamic mmap
threshold to the block's size (up to 32 MB), so the next rebuild's tables come
from the heap instead, whose freed middle is never returned. Resident memory
then settles at a rebuild's peak, old and new sets together. The shipped unit
pins the threshold with MALLOC_MMAP_THRESHOLD_, which also turns the adjustment
off.

The case rebuilds one list over SIGHUP in two processes: one started with the
environment `packaging/elodin.service` sets, which has to stay near the RSS it
started with, and one without it - the premise, which has to grow. Under a
sanitizer's allocator, or where the control does not grow (musl), there is
nothing to measure, and the case is skipped rather than passed.
*/

/*
How much memory a rebuild keeps depends on where the tables' sizes fall against
the threshold glibc has moved to, so the premise holds at some sizes and not
others: half a million names of a realistic length, about 23 MB of list, keep
roughly as much again as the process started with.
*/
@(private = "file")
MEMORY_RULES :: 500_000

@(private = "file")
MEMORY_RELOADS :: 4

@(private = "file")
UNIT_FILE :: "packaging/elodin.service"

// The `KEY=VALUE` assignments of the unit's Environment= lines. Quoting,
// specifiers, an empty line (which resets the list) and a key set twice (where
// systemd takes the last and getenv the first) are refused rather than
// interpreted, so a value this does not read cannot pass as one.
@(private = "file")
unit_environment :: proc(r: ^Runner) -> (env: [dynamic]string, ok: bool) {
	data, err := os.read_entire_file(UNIT_FILE, context.temp_allocator)
	if err != nil {
		fail(r, "cannot read %s: %v", UNIT_FILE, err)
		return
	}
	env = make([dynamic]string, context.temp_allocator)
	text := string(data)
	for line in strings.split_lines_iterator(&text) {
		if !strings.has_prefix(line, "Environment=") {
			continue
		}
		value := line[len("Environment="):]
		if strings.contains_any(value, `"'\%`) || strings.trim_space(value) == "" {
			fail(r, "%s: %q is not read here", UNIT_FILE, line)
			return
		}
		for field in strings.fields(value, context.temp_allocator) {
			key := field[:strings.index_byte(field, '=') + 1]
			for set in env {
				if key != "" && strings.has_prefix(set, key) {
					fail(r, "%s: %s is set twice", UNIT_FILE, key)
					return
				}
			}
			append(&env, field)
		}
	}
	return env, true
}

@(private = "file")
list_memory_config :: proc(udp_port: int, list_path: string, timeout_s: int) -> string {
	return fmt.tprintf(
		`log: {{ level: info }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: %ds
  servers: ["127.0.0.1:1"]
cache: {{ enabled: false }}
blocking:
  enabled: true
  lists:
    - {{ name: big, file: %s, format: hosts }}
`,
		udp_port,
		timeout_s,
		list_path,
	)
}

@(private = "file")
rss_kib :: proc(pid: int) -> (kib: int, ok: bool) {
	data, err := os.read_entire_file(fmt.tprintf("/proc/%d/status", pid), context.temp_allocator)
	if err != nil {
		return
	}
	text := string(data)
	for line in strings.split_lines_iterator(&text) {
		if strings.has_prefix(line, "VmRSS:") {
			return strconv.parse_int(strings.trim_space(strings.trim_suffix(line[len("VmRSS:"):], "kB")))
		}
	}
	return
}

/*
Start a server on the list, rebuild it MEMORY_RELOADS times, and report its RSS
once ready and after the last rebuild. Each reload changes `upstream.timeout`,
so it takes the path that logs `reloaded` only once the old sets are freed.
*/
@(private = "file")
rss_across_rebuilds :: proc(r: ^Runner, env: []string, list_path: string) -> (start, end: int, ok: bool) {
	udp_port := next_port(r)
	srv, started := start_server_raw(r, list_memory_config(udp_port, list_path, 2), udp_port, env = env)
	if !started {
		return
	}
	defer stop_server(&srv)
	if !check(r, wait_ready(&srv, 60 * time.Second), "the server never became ready; log:\n%s", read_log(&srv)) {
		return
	}
	start, ok = rss_kib(srv.process.pid)
	if !check(r, ok, "cannot read the server's VmRSS") {
		return
	}

	cfg_path := filepath.join({r.work_dir, fmt.tprintf("elodin-%d.yaml", udp_port)}, context.temp_allocator) or_else ""
	for i in 1 ..= MEMORY_RELOADS {
		before := log_count(&srv, "msg=reloaded")
		written := without_dnssec(list_memory_config(udp_port, list_path, 2 + i % 2))
		if !check(r, os.write_entire_file(cfg_path, transmute([]u8)written) == nil, "cannot rewrite %s", cfg_path) ||
		   !check(r, signal_reload(&srv), "could not deliver SIGHUP") ||
		   !check(r, wait_for_log_count(&srv, "msg=reloaded", before + 1, 60 * time.Second), "reload %d never finished; log:\n%s", i, read_log(&srv)) {
			return start, 0, false
		}
	}
	end, ok = rss_kib(srv.process.pid)
	check(r, ok, "cannot read the server's VmRSS")
	return
}

run_list_memory_cases :: proc(r: ^Runner) {
	NAME :: "lists: a rebuild under the shipped unit's environment gives the old sets' memory back"

	// Its failure is already a setup failure, and a skip would count it twice.
	unit_env, unit_ok := unit_environment(r)
	if !unit_ok {
		return
	}

	// A sanitizer's runtime answers malloc itself and ignores glibc's settings,
	// and its quarantine grows both processes alike.
	exe, xerr := os.read_entire_file(r.binary, context.temp_allocator)
	if xerr != nil {
		skip_case(r, NAME, "cannot read the binary")
		return
	}
	if strings.contains(string(exe), "__asan_init") {
		skip_case(r, NAME, "the binary is built with AddressSanitizer, whose allocator is not glibc's")
		return
	}

	// Heap: the deferred removal runs after `end_case` has reset the temp
	// allocator.
	list_path := filepath.join({r.work_dir, "list-memory.txt"}, context.allocator) or_else ""
	defer delete(list_path)
	b := strings.builder_make(context.temp_allocator)
	for i in 0 ..< MEMORY_RULES {
		fmt.sbprintfln(&b, "0.0.0.0 host%07d.sub%d.example-blocked-domain.test", i, i % 97)
	}
	if os.write_entire_file(list_path, b.buf[:]) != nil {
		skip_case(r, NAME, "cannot write the list")
		return
	}
	defer os.remove(list_path)

	// Without any MALLOC_ setting or GLIBC_TUNABLES of the suite's own (either
	// sets the threshold), so the control is the allocator's defaults and the
	// unit's arm is only what the unit sets.
	inherited, eerr := os.environ(context.temp_allocator)
	if eerr != nil {
		skip_case(r, NAME, "cannot read the environment")
		return
	}
	control := make([dynamic]string, context.temp_allocator)
	for kv in inherited {
		if !strings.has_prefix(kv, "MALLOC_") && !strings.has_prefix(kv, "GLIBC_TUNABLES=") {
			append(&control, kv)
		}
	}
	shipped := make([dynamic]string, context.temp_allocator)
	append(&shipped, ..control[:])
	append(&shipped, ..unit_env[:])

	// Outside the case, so a control that cannot run fails as setup and one
	// that does not grow is a skip, not a pass.
	c0, c1, cok := rss_across_rebuilds(r, control[:], list_path)
	if !cok {
		return
	}
	// The premise: the defaults keep a rebuild's peak, here at least half as
	// much again as the process started with.
	if c1 * 2 < c0 * 3 {
		skip_case(r, NAME, fmt.tprintf("the allocator returns the memory without the unit's setting (%d -> %d KiB)", c0, c1))
		return
	}

	start_case(r, NAME)
	if u0, u1, uok := rss_across_rebuilds(r, shipped[:], list_path); uok {
		check(
			r,
			u1 * 4 <= u0 * 5,
			"RSS went %d -> %d KiB over %d rebuilds with the unit's environment %v (%d -> %d KiB without it)",
			u0,
			u1,
			MEMORY_RELOADS,
			unit_env[:],
			c0,
			c1,
		)
	}
	end_case(r)
}
