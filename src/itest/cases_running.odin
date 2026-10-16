package itest

import "core:fmt"
import "core:net"
import "core:strings"
import "core:time"
import "elodin:dns"

/*
The running limit, against the running binary.

`server.running_workers` caps how many of the pool's workers are on the CPU at
once, and a worker waiting on the network or on another query does not count
against it. What a client can see of that is the second half: with one running
worker, queries that each wait on a slow upstream still overlap, and the cases
here hold a single slot while something waits in each of the places a handler
waits - an upstream round trip, a coalesced follower, a DoH reply parked on the
client's flow-control window. A wait the pool did not know about would show as
the other queries arriving one round trip, or one write timeout, late.

The upstream answers after `DELAY`, and each bound sits half a delay past one
round trip: what a missed wait costs is a whole round trip more, at least.
*/

@(private = "file")
DELAY :: 600 * time.Millisecond

@(private = "file")
WITHIN :: DELAY + DELAY / 2

@(private = "file")
config_running :: proc(r: ^Runner, udp_port, doh_port, upstream_port: int, server: string) -> string {
	doh := "doh: { enabled: false }"
	if doh_port > 0 {
		doh = fmt.tprintf(
			`doh: {{ enabled: true, address: "127.0.0.1", port: %d, path: /dns-query, cert_file: %s, key_file: %s }}`,
			doh_port,
			r.cert_file,
			r.key_file,
		)
	}
	return fmt.tprintf(
		`log: {{ level: info }}
server:
%s
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
  %s
upstream:
  timeout: 5s
  attempts: 1
  servers: ["127.0.0.1:%d"]
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		server,
		udp_port,
		doh,
		upstream_port,
	)
}

/*
Send every query at once, each from a socket of its own, and wait for them all.
How many were answered, and how long the last one took.
*/
@(private = "file")
udp_burst :: proc(udp_port: int, queries: [][]u8) -> (answered: int, elapsed: time.Duration) {
	sockets := make([]net.UDP_Socket, len(queries), context.temp_allocator)
	opened := make([]bool, len(queries), context.temp_allocator)
	defer for s, i in sockets {
		if opened[i] {
			net.close(s)
		}
	}
	endpoint := net.Endpoint {
		address = net.IP4_Loopback,
		port    = udp_port,
	}
	start := time.tick_now()
	for q, i in queries {
		s, err := net.make_unbound_udp_socket(.IP4)
		if err != nil {
			continue
		}
		sockets[i] = s
		opened[i] = true
		_, _ = net.send_udp(s, q, endpoint)
	}
	deadline := time.tick_add(start, CLIENT_TIMEOUT)
	buf := make([]u8, 65535, context.temp_allocator)
	for s, i in sockets {
		if !opened[i] {
			continue
		}
		left := time.tick_diff(time.tick_now(), deadline)
		if left <= 0 {
			break
		}
		_ = net.set_option(s, .Receive_Timeout, left)
		n, _, rerr := net.recv_udp(s, buf)
		if rerr == nil && n >= dns.HEADER_SIZE {
			answered += 1
		}
	}
	return answered, time.tick_since(start)
}

@(private = "file")
burst_queries :: proc(prefix: string, n: int, first_id: u16) -> [][]u8 {
	queries := make([][]u8, n, context.temp_allocator)
	for i in 0 ..< n {
		queries[i] = build_query(
			fmt.tprintf("%s%d.example.", prefix, i),
			u16(dns.Type.A),
			id = first_id + u16(i),
			allocator = context.temp_allocator,
		)
	}
	return queries
}

run_running_worker_cases :: proc(r: ^Runner, cert_ok: bool) {
	upstream_port := next_port(r)
	mock := mock_make("running", upstream_port)
	// No payload: an empty NOERROR for whatever was asked, so every name is
	// its own question and its own round trip.
	mock_delay_all(mock, DELAY, nil)
	if !mock_start(mock) {
		skip_case(r, "server.running_workers", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	doh_port := next_port(r) if cert_ok else 0
	srv, ok := start_server(
		r,
		Server_Options {
			config = config_running(
				r,
				udp_port,
				doh_port,
				upstream_port,
				"  workers: 8\n  running_workers: 1\n  client_timeout: 5s\n  rate_limit: { enabled: false }",
			),
			udp_port = udp_port,
			doh_port = doh_port,
			warmup = DELAY,
		},
	)
	if !ok {
		skip_case(r, "server.running_workers", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "running_workers: one running worker still overlaps queries waiting on the upstream")
	{
		check(
			r,
			log_contains(&srv, "running_workers=1"),
			"the sizing line does not report the configured limit; log:\n%s",
			read_log(&srv),
		)
		answered, elapsed := udp_burst(udp_port, burst_queries("overlap", 8, 0x5100))
		check_eq_int(r, answered, 8, "queries answered")
		// One at a time would be eight round trips.
		check(
			r,
			elapsed < WITHIN,
			"8 queries against a %v upstream took %v on one running worker: the round trips did not overlap",
			DELAY,
			elapsed,
		)
	}
	end_case(r)

	start_case(r, "running_workers: a coalesced follower does not hold the running slot")
	{
		/*
		One name three times, then four of their own. The first is the leader
		and waits on the upstream; the next two wait on the leader, which is
		the wait under test. Held, the slot keeps the four behind it until the
		leader lands, and they reach the upstream a round trip late.
		*/
		same := build_query("coalesced.example.", u16(dns.Type.A), id = 0x5200, allocator = context.temp_allocator)
		queries := make([dynamic][]u8, context.temp_allocator)
		for _ in 0 ..< 3 {
			append(&queries, same)
		}
		append(&queries, ..burst_queries("beside", 4, 0x5210))
		answered, elapsed := udp_burst(udp_port, queries[:])
		check_eq_int(r, answered, 7, "queries answered")
		check(
			r,
			elapsed < WITHIN,
			"took %v against a %v upstream: the queries behind the followers waited for the leader",
			elapsed,
			DELAY,
		)
	}
	end_case(r)

	if cert_ok {
		start_case(r, "running_workers: a DoH reply parked on flow control does not hold the running slot")
		{
			// A one-byte window: the reply's first DATA frame carries one byte
			// and the rest waits on credit this client never gives, up to the
			// write timeout (`client_timeout`, 5 s here).
			c, cok := h2_connect(doh_port, H2_Settings{initial_window = 1})
			if check(r, cok, "cannot open an h2 connection") {
				defer h2_close(c)
				q := build_query("parked.example.", u16(dns.Type.A), id = 0x5300, allocator = context.temp_allocator)
				check(r, h2_send_request(c, 1, "POST", "/dns-query", q), "cannot send")
				stalled := false
				deadline := time.tick_add(time.tick_now(), CLIENT_TIMEOUT)
				for time.tick_diff(time.tick_now(), deadline) > 0 {
					if res, found := h2_stream(c, 1); found && res.data_frames >= 1 {
						stalled = true
						break
					}
					if !h2_pump(c) {
						break
					}
				}
				if check(r, stalled, "the reply never started, so nothing is parked on the window") {
					answered, elapsed := udp_burst(udp_port, burst_queries("past-parked", 2, 0x5310))
					check_eq_int(r, answered, 2, "queries answered")
					check(
						r,
						elapsed < WITHIN,
						"took %v against a %v upstream while a DoH reply waited on flow control",
						elapsed,
						DELAY,
					)
				}
			}
		}
		end_case(r)
	}

	/*
	A handler under `strategy: race` waits on its racers rather than on a
	socket. Racers run on a pool of their own, sized here so that it is not
	what holds the queries back.
	*/
	start_case(r, "running_workers: a handler waiting on its racers does not hold the running slot")
	{
		second_port := next_port(r)
		second := mock_make("running-race", second_port)
		mock_delay_all(second, DELAY, nil)
		if check(r, mock_start(second), "cannot start the second mock upstream") {
			defer mock_stop(second)
			race_port := next_port(r)
			race_config, _ := strings.replace(
				config_running(
					r,
					race_port,
					0,
					upstream_port,
					"  workers: 8\n  running_workers: 1\n  upstream_workers: 16\n  rate_limit: { enabled: false }",
				),
				fmt.tprintf("  servers: [\"127.0.0.1:%d\"]", upstream_port),
				fmt.tprintf(
					"  strategy: race\n  servers: [\"127.0.0.1:%d\", \"127.0.0.1:%d\"]",
					upstream_port,
					second_port,
				),
				1,
				context.temp_allocator,
			)
			rsrv, rok := start_server(r, Server_Options{config = race_config, udp_port = race_port, warmup = DELAY})
			if check(r, rok, "server did not start") {
				defer stop_server(&rsrv)
				answered, elapsed := udp_burst(race_port, burst_queries("raced", 4, 0x5500))
				check_eq_int(r, answered, 4, "queries answered")
				check(
					r,
					elapsed < WITHIN,
					"4 raced queries against %v upstreams took %v on one running worker",
					DELAY,
					elapsed,
				)
			}
		}
	}
	end_case(r)

	/*
	A client served from an expired entry waits up to `stale_timeout` for the
	refresh it started, and the refresh runs on this same pool. Held, the slot
	would leave the refresh queued behind the very worker waiting for it, and
	the client would get the stale answer at the timer rather than the fresh
	one a round trip in.
	*/
	start_case(r, "running_workers: a client waiting on its stale refresh does not hold the running slot")
	{
		qname := "stale-slot.example."
		stale_port := next_port(r)
		stale_mock := mock_make("running-stale", stale_port)
		mock_delay_all(stale_mock, 200 * time.Millisecond, make_a_response(qname, {203, 0, 113, 9}, 60, context.allocator))
		if check(r, mock_start(stale_mock), "cannot start the stale mock upstream") {
			defer mock_stop(stale_mock)
			udp := next_port(r)
			stale_config, _ := strings.replace(
				config_running(r, udp, 0, stale_port, "  workers: 8\n  running_workers: 1\n  rate_limit: { enabled: false }"),
				"cache: { enabled: false }",
				"cache: { enabled: true, max_entries: 100, max_ttl: 1, serve_stale: true, stale_timeout: 2s }",
				1,
				context.temp_allocator,
			)
			ssrv, sok := start_server(r, Server_Options{config = stale_config, udp_port = udp, warmup = DELAY})
			if check(r, sok, "server did not start") {
				defer stop_server(&ssrv)
				first := query_udp(udp, build_query(qname, u16(dns.Type.A), id = 0x5600), context.temp_allocator)
				if check(r, first.ok, "no answer to fill the cache") {
					// Past `max_ttl`, which the entry was stored under.
					time.sleep(1300 * time.Millisecond)
					begun := time.tick_now()
					second := query_udp(udp, build_query(qname, u16(dns.Type.A), id = 0x5601), context.temp_allocator)
					waited := time.tick_since(begun)
					check(r, second.ok, "no answer from the expired entry")
					check(
						r,
						waited < time.Second,
						"waited %v for a 200ms refresh: it ran only once the 2s stale timer let the slot go",
						waited,
					)
				}
			}
		}
	}
	end_case(r)

	/*
	The derived sizing, which is what an installation that names no number
	gets: a pool as wide as the memory allows, whatever the core count, so a
	burst of misses wider than the cores still overlaps its round trips.
	*/
	start_case(r, "running_workers: the derived pool carries a burst of 64 misses in one round trip")
	{
		derived_port := next_port(r)
		dsrv, dok := start_server(
			r,
			Server_Options {
				config = config_running(r, derived_port, 0, upstream_port, "  rate_limit: { enabled: false }"),
				udp_port = derived_port,
				warmup = DELAY,
			},
		)
		if check(r, dok, "server did not start") {
			defer stop_server(&dsrv)
			check(
				r,
				log_contains(&dsrv, "running_workers="),
				"the sizing line does not report the running limit; log:\n%s",
				read_log(&dsrv),
			)
			answered, elapsed := udp_burst(derived_port, burst_queries("derived", 64, 0x5400))
			check_eq_int(r, answered, 64, "queries answered")
			check(
				r,
				elapsed < WITHIN,
				"64 misses against a %v upstream took %v with the derived sizing",
				DELAY,
				elapsed,
			)
		}
	}
	end_case(r)
}
