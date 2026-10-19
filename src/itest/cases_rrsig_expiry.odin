package itest

import "core:fmt"
import "core:time"
import "elodin:dns"

/*
Issue #165: a cached answer is not served past its signatures, fresh or stale.

RFC 4034 section 3.1.5: an RRSIG "MUST NOT be used for authentication after the
expiration date". The mock answers with an A record and an RRSIG over it that
expires two seconds from now. Validation is off, so nothing here has checked the
signature and the cache is the only thing that can hold to it. The answer must
go out telling the client no more than the signature has left. Once the clock is
past the expiration, with the upstream silent, `serve_stale` must not hand the
day-long stale copy out; the client is answered SERVFAIL instead.
*/
@(private = "file")
RX_QNAME :: "signed.stale.example."

// The answer the mock serves, its RRSIG lapsing at `expiration`.
@(private = "file")
rx_answer :: proc(expiration: u32) -> []u8 {
	sig := make([]u8, 31, context.allocator)
	copy(sig, []u8{0, 1, 13, 3, 0, 0, 0x0e, 0x10})
	dns.write_ttl_at(sig, 8, expiration)
	dns.write_ttl_at(sig, 12, expiration - 86400) // inception
	copy(sig[16:], []u8{0x12, 0x34, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0xde, 0xad, 0xbe, 0xef})
	question := make([]dns.Question, 1, context.allocator)
	question[0] = {name = RX_QNAME, type = .A, class = .IN}
	answer := make([]dns.Record, 2, context.allocator)
	answer[0] = {name = RX_QNAME, type = .A, class = .IN, ttl = 3600, data = dns.Rdata_A{addr = {203, 0, 113, 65}}}
	answer[1] = {name = RX_QNAME, type = .RRSIG, class = .IN, ttl = 3600, data = dns.Rdata_Raw{data = sig}}
	m := dns.Message {
		id       = 0x1650,
		question = question,
		answer   = answer,
	}
	m.flags.qr = true
	m.flags.rd = true
	m.flags.ra = true
	wire, _, _ := dns.encode_message(m, context.allocator)
	return wire
}

@(private = "file")
rx_config :: proc(udp_port, upstream_port: int) -> string {
	return fmt.tprintf(
		`log: {{ level: warn }}
listeners:
  udp: {{ enabled: true, address: "127.0.0.1", port: %d }}
  tcp: {{ enabled: false }}
upstream:
  timeout: 1s
  attempts: 1
  servers: ["127.0.0.1:%d"]
cache:
  enabled: true
  max_entries: 100
  serve_stale: true
  stale_timeout: 300ms
dnssec: {{ enabled: false }}
blocking: {{ enabled: false }}
`,
		udp_port,
		upstream_port,
	)
}

run_rrsig_expiry_cases :: proc(r: ^Runner) {
	expiration := u32(time.time_to_unix(time.now())) + 2
	upstream_port := next_port(r)
	mock := mock_make("rrsig-expiry", upstream_port)
	mock_reply(mock, RX_QNAME, u16(dns.Type.A), rx_answer(expiration))
	if !mock_start(mock) {
		skip_case(r, "cache: rrsig expiry", "cannot start the mock upstream")
		return
	}
	defer mock_stop(mock)

	udp_port := next_port(r)
	config := rx_config(udp_port, upstream_port)
	srv, ok := start_server(r, Server_Options{config = config, udp_port = udp_port})
	if !ok {
		skip_case(r, "cache: rrsig expiry", "server did not start")
		return
	}
	defer stop_server(&srv)

	start_case(r, "cache: a signed answer is told no more ttl than its rrsig has left")
	{
		res := query_udp(udp_port, build_query(RX_QNAME, u16(dns.Type.A), id = 1, edns_size = 1232, dnssec_ok = true))
		if check(r, res.ok, "no response to the query that filled the cache") {
			ttl, has := min_answer_ttl(r, res.wire)
			check(r, has && ttl <= 2, "the answer went out with ttl %d; its rrsig has 2 s left", ttl)
		}
	}
	end_case(r)

	start_case(r, "cache: serve_stale does not serve an answer past its rrsig")
	{
		// Wait for the clock, not a duration: the case is about the expiration
		// second having passed.
		for u32(time.time_to_unix(time.now())) <= expiration {
			time.sleep(100 * time.Millisecond)
		}
		mock_go_silent(mock)
		res := query_udp(udp_port, build_query(RX_QNAME, u16(dns.Type.A), id = 2, edns_size = 1232, dnssec_ok = true))
		if check(r, res.ok, "no response once the upstream went silent") {
			h := parse_header(r, res.wire)
			check_eq_int(r, h.rcode, int(dns.Rcode.Serv_Fail), "rcode once the only copy's rrsig has expired")
		}
	}
	end_case(r)
}
