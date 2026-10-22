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
started with, and one without it - the premise, which has to grow. A control
that does not grow fails the case: the check would pass whatever the unit set,
so the list's size needs moving back into the band where glibc keeps the
memory. Under a sanitizer, whose allocator is not glibc's, it is skipped.
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
// specifiers, an empty line (which resets the list), an assignment without `=`,
// a key set twice (where systemd takes the last and getenv the first), an
// Environment= outside [Service] (which systemd ignores) and any other
// environment directive (UnsetEnvironment=, EnvironmentFile=, PassEnvironment=)
// are refused rather than interpreted, so a value this does not read cannot
// pass as one.
@(private = "file")
unit_environment :: proc(r: ^Runner) -> (env: [dynamic]string, ok: bool) {
	data, err := os.read_entire_file(UNIT_FILE, context.temp_allocator)
	if err != nil {
		fail(r, "cannot read %s: %v", UNIT_FILE, err)
		return
	}
	env = make([dynamic]string, context.temp_allocator)
	text := string(data)
	in_service := false
	for raw in strings.split_lines_iterator(&text) {
		// systemd strips ASCII blanks around the directive and its `=`.
		line := strings.trim_left(raw, " \t")
		if strings.has_prefix(line, "[") {
			in_service = strings.trim_right(line, " \t\r") == "[Service]"
			continue
		}
		eq := strings.index_byte(line, '=')
		if eq < 0 || strings.has_prefix(line, "#") || strings.has_prefix(line, ";") {
			continue
		}
		directive := strings.trim_right(line[:eq], " \t")
		if !strings.contains(directive, "Environment") {
			continue
		}
		value := line[eq + 1:]
		if directive != "Environment" || !in_service || strings.contains_any(value, `"'\%`) || strings.trim_space(value) == "" {
			fail(r, "%s: %q is not read here", UNIT_FILE, line)
			return
		}
		// systemd splits on ASCII blanks only, where `strings.fields` also
		// splits on \v, \f and Unicode spaces.
		for field in strings.fields_proc(value, proc(c: rune) -> bool {return c == ' ' || c == '\t' || c == '\r'}, context.temp_allocator) {
			sep := strings.index_byte(field, '=')
			if sep <= 0 {
				fail(r, "%s: %q is not an assignment", UNIT_FILE, field)
				return
			}
			key := field[:sep + 1]
			for set in env {
				if strings.has_prefix(set, key) {
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
	value := proc_status_field(fmt.tprintf("/proc/%d/status", pid), "VmRSS") or_return
	return strconv.parse_int(strings.trim_space(strings.trim_suffix(value, "kB")))
}

/*
Start a server on the list, rebuild it MEMORY_RELOADS times, and report its RSS
once ready and after the last rebuild. Each reload changes `upstream.timeout`
and rereads the `file:` list; the rebuild that follows logs its `filter:` line
once the old sets are freed.
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

	for i in 1 ..= MEMORY_RELOADS {
		reloaded := reload_to(r, &srv, list_memory_config(udp_port, list_path, 2 + i % 2), "block rules (", 60 * time.Second)
		if !check(r, reloaded, "reload %d never finished; log:\n%s", i, read_log(&srv)) {
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
	// Heap, as the list below: the temp allocator is not reset until the next
	// case ends, and a skip from here ends none.
	exe, xerr := os.read_entire_file(r.binary, context.allocator)
	if xerr != nil {
		fail(r, "%s: cannot read %s: %v", NAME, r.binary, xerr)
		return
	}
	asan := strings.contains(string(exe), "__asan_init")
	delete(exe)
	if asan {
		skip_case(r, NAME, "the binary is built with AddressSanitizer, whose allocator is not glibc's")
		return
	}

	// Heap: the deferred removal runs after `end_case` has reset the temp
	// allocator.
	list_path := filepath.join({r.work_dir, "list-memory.txt"}, context.allocator) or_else ""
	defer delete(list_path)
	b := strings.builder_make(context.allocator)
	for i in 0 ..< MEMORY_RULES {
		fmt.sbprintfln(&b, "0.0.0.0 host%07d.sub%d.example-blocked-domain.test", i, i % 97)
	}
	werr := os.write_entire_file(list_path, b.buf[:])
	strings.builder_destroy(&b)
	if werr != nil {
		fail(r, "%s: cannot write %s: %v", NAME, list_path, werr)
		return
	}
	defer os.remove(list_path)

	// Without any MALLOC_ setting or GLIBC_TUNABLES of the suite's own (either
	// sets the threshold) or an LD_PRELOAD (which can replace the allocator), so
	// the control is glibc's defaults and the unit's arm is only what the unit
	// sets. Its capacity keeps `control[:]` non-nil when every variable is
	// dropped: a nil environment is the suite's own, MALLOC_ settings included.
	inherited, eerr := os.environ(context.temp_allocator)
	if eerr != nil {
		fail(r, "%s: cannot read the environment: %v", NAME, eerr)
		return
	}
	control := make([dynamic]string, 0, len(inherited), context.temp_allocator)
	for kv in inherited {
		if !strings.has_prefix(kv, "MALLOC_") && !strings.has_prefix(kv, "GLIBC_TUNABLES=") && !strings.has_prefix(kv, "LD_PRELOAD=") {
			append(&control, kv)
		}
	}
	// The unit's first: getenv takes the first of a key set twice, and under
	// systemd the unit's value is the one the process sees.
	shipped := make([dynamic]string, context.temp_allocator)
	append(&shipped, ..unit_env[:])
	append(&shipped, ..control[:])

	start_case(r, NAME)
	c0, c1, cok := rss_across_rebuilds(r, control[:], list_path)
	// The premise: the defaults keep a rebuild's peak, here at least half as
	// much again as the process started with.
	premise :=
		cok &&
		check(
			r,
			c1 * 2 >= c0 * 3,
			"without the unit's environment RSS went only %d -> %d KiB over %d rebuilds, so this cannot tell whether the unit's setting works; move MEMORY_RULES back to a size glibc keeps",
			c0,
			c1,
			MEMORY_RELOADS,
		)
	if premise {
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
	}
	end_case(r)
}
