package itest

import "core:fmt"
import "core:net"
import "core:os"
import "core:time"

/*
elodin as a DoH client: ALPN decides between HTTP/2 and HTTP/1.1 against the
upstream, exactly as it does the other way around for elodin's own DoH
listener (cases_h2.odin). See src/upstream/h2client.odin.
*/
run_upstream_doh2_cases :: proc(r: ^Runner) {
	fix := fixture("a")
	payload := from_hex(fix.response, context.allocator)

	// --- ALPN prefers h2 when the upstream offers it ---
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		if !doh2_mock_start(mock, r.cert_file, r.key_file) {
			skip_case(r, "upstream: doh over h2", "cannot start the mock")
		} else {
			defer doh2_mock_stop(mock)
			udp_port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  servers:
    - {{ name: doh2up, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				udp_port,
				upstream_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: resolves a query over a DoH/h2 upstream")
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype))
					if check(r, res.ok, "no response") {
						h := parse_header(r, res.wire)
						check_eq_int(r, h.ancount, fix.ancount, "answer count")
					}
					h2_hits, h1_hits := doh2_mock_counts(mock)
					check(r, h2_hits >= 1, "the upstream was not reached over h2")
					check_eq_int(r, h1_hits, 0, "fell back to http/1.1 against an h2-capable upstream")
				}
				end_case(r)

				start_case(r, "upstream: DoH/h2 connection is multiplexed across queries, not reopened")
				{
					before_h2, _ := doh2_mock_counts(mock)
					for i in 0 ..< 5 {
						res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(500 + i)))
						check(r, res.ok, "no response on query %d", i)
					}
					after_h2, _ := doh2_mock_counts(mock)
					// Every query answered over h2, but on the one shared connection:
					// hits (streams) go up while the mock only ever accepts once.
					check_eq_int(r, after_h2 - before_h2, 5, "streams answered over h2")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: doh over h2", "server did not start")
			}
		}
	}

	// --- ALPN falls back to http/1.1 against a resolver that lacks h2 ---
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		if !doh2_mock_start(mock, r.cert_file, r.key_file, {"http/1.1"}) {
			skip_case(r, "upstream: doh h2 alpn fallback", "cannot start the mock")
		} else {
			defer doh2_mock_stop(mock)
			udp_port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  servers:
    - {{ name: h1up, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				udp_port,
				upstream_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: falls back to http/1.1 when the upstream does not offer h2")
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype))
					if check(r, res.ok, "no response") {
						h := parse_header(r, res.wire)
						check_eq_int(r, h.ancount, fix.ancount, "answer count")
					}
					h2_hits, h1_hits := doh2_mock_counts(mock)
					check_eq_int(r, h2_hits, 0, "used h2 against an upstream that only offered http/1.1")
					check(r, h1_hits >= 1, "the upstream was not reached over http/1.1")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: doh h2 alpn fallback", "server did not start")
			}
		}
	}

	// --- a race member over HTTP/1.1 answering 503 with a body ---
	/*
	The race path takes replies from the heap and frees them only when they
	win, so a refused reply's body is the exchange's to release (#524). Under
	`mise run leakcheck` a body left behind is a report; here the case pins that
	the 503 path is the one taken and that the race rides through it.
	*/
	{
		down_port := next_port(r)
		up_port := next_port(r)
		down := doh2_mock_make(down_port, "/dns-query", payload)
		down.status = 503
		up := doh2_mock_make(up_port, "/dns-query", payload)
		if !doh2_mock_start(down, r.cert_file, r.key_file, {"http/1.1"}) {
			skip_case(r, "upstream: doh h1 503 in a race", "cannot start the mock")
		} else if !doh2_mock_start(up, r.cert_file, r.key_file) {
			doh2_mock_stop(down)
			skip_case(r, "upstream: doh h1 503 in a race", "cannot start the mock")
		} else {
			defer doh2_mock_stop(down)
			defer doh2_mock_stop(up)
			udp_port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  strategy: race
  servers:
    - {{ name: down, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}
    - {{ name: up, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				udp_port,
				down_port,
				up_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: a race rides through an HTTP/1.1 member answering 503 with a body")
				{
					for i in 0 ..< 3 {
						res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = u16(0x5240 + i)))
						if check(r, res.ok, "query %d: no response", i) {
							h := parse_header(r, res.wire)
							check_eq_int(r, h.ancount, fix.ancount, "answer count")
						}
					}
					// The race answers with the first member, so the 503 member's own
					// dial may still be under way when the last answer arrives.
					h1_hits := 0
					asked_by := time.tick_add(time.tick_now(), 5 * time.Second)
					for {
						_, h1_hits = doh2_mock_counts(down)
						if h1_hits >= 1 || time.tick_diff(time.tick_now(), asked_by) <= 0 {
							break
						}
						time.sleep(10 * time.Millisecond)
					}
					check(r, h1_hits >= 1, "the 503 member was never asked, so its body was never read")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: doh h1 503 in a race", "server did not start")
			}
		}
	}

	// --- an HTTP/1.1 reply longer than a DNS message ---
	/*
	RFC 8484 6 holds application/dns-message to 65535 bytes, so a 96 KB reply is
	refused even though it echoes the query's header and question, rather than
	taken as the answer at twice its length per query (#525).
	*/
	{
		upstream_port := next_port(r)
		mock := doh2_mock_make(upstream_port, "/dns-query", payload)
		mock.pad = 98304
		if !doh2_mock_start(mock, r.cert_file, r.key_file, {"http/1.1"}) {
			skip_case(r, "upstream: doh h1 oversized reply", "cannot start the mock")
		} else {
			defer doh2_mock_stop(mock)
			udp_port := next_port(r)
			config := fmt.tprintf(
				`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 5s
  servers:
    - {{ name: big, type: https, url: "https://127.0.0.1:%d/dns-query", verify: false }}
cache: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
				udp_port,
				upstream_port,
			)
			srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
			if ok {
				start_case(r, "upstream: a DoH reply over HTTP/1.1 longer than a DNS message is refused")
				{
					res := query_udp(udp_port, build_query(fix.qname, fix.qtype, id = 0x5250))
					if check(r, res.ok, "no response") {
						h := parse_header(r, res.wire)
						check_eq_int(r, h.rcode, 2, "rcode (SERVFAIL)")
					}
					_, h1_hits := doh2_mock_counts(mock)
					check(r, h1_hits >= 1, "the oversized member was never asked over HTTP/1.1")
				}
				end_case(r)
				stop_server(&srv)
			} else {
				skip_case(r, "upstream: doh h1 oversized reply", "server did not start")
			}
		}
	}

	// --- a mock that cannot bind its port can still be stopped ---
	/*
	Another run on the box holding the port is how a parity scenario's mock
	fails to start, and the scenario stops every mock it made, started or not.
	So a failed start keeps no handle it has already freed or closed: the stop
	would free the TLS context a second time, or close a number that may by
	then be another socket.
	*/
	{
		port := next_port(r)
		held, herr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = port})
		if herr != nil {
			skip_case(r, "harness: a mock that cannot bind", "cannot hold the port")
		} else {
			start_case(r, "harness: a mock that cannot bind its port can still be stopped")
			mock := doh2_mock_make(port, "/dns-query", payload)
			check(r, !doh2_mock_start(mock, r.cert_file, r.key_file), "the doh mock started on a port already held")
			check(r, mock.tls_ctx == nil, "the failed start kept a TLS context it had freed")
			doh2_mock_stop(mock)
			dot := mock_make("held", port)
			check(r, !mock_start(dot, r.cert_file, r.key_file), "the dot mock started on a port already held")
			check(r, dot.tls_ctx == nil, "the failed start kept a TLS context a caller that skips the stop leaks")
			mock_stop(dot)
			// The UDP port is free, so the plain mock binds it and then fails on
			// TCP, closing the UDP socket it already had.
			probe, perr := net.make_bound_udp_socket(net.IP4_Loopback, port)
			if probe != 0 {
				net.close(probe)
			}
			check(r, perr == nil, "the UDP port is taken, so the start never reaches the TCP listen")
			plain := mock_make("held", port)
			check(r, !mock_start(plain), "the mock started on a port already held")
			check(r, plain.udp_socket == 0, "the failed start kept a UDP socket it had closed")
			mock_stop(plain)
			// With the UDP port held instead, the bind fails first, and the
			// socket it could not bind is closed rather than left open.
			held_udp, uerr := net.make_bound_udp_socket(net.IP4_Loopback, port)
			if check(r, uerr == nil, "cannot hold the UDP port") {
				before := open_fds()
				udp_only := mock_make("held", port)
				check(r, !mock_start(udp_only), "the mock started on a UDP port already held")
				mock_stop(udp_only)
				check(r, open_fds() == before, "the failed UDP bind left its socket open")
			}
			if held_udp != 0 {
				net.close(held_udp)
			}
			end_case(r)
			net.close(held)
		}
	}

	delete(payload)
}

// How many descriptors this process has open, or -1 when /proc cannot say.
@(private = "file")
open_fds :: proc() -> int {
	entries, err := os.read_directory_by_path("/proc/self/fd", -1, context.temp_allocator)
	if err != nil {
		return -1
	}
	return len(entries)
}
