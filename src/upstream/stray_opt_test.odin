package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:dns"

/*
Issue #353: a reply carrying an OPT record outside the additional section is
malformed (RFC 6891 section 6.1.1), and the group goes on to a member that
answers properly - the reading Unbound and BIND give it.
*/

@(private = "file")
Opt_Mock :: struct {
	socket: net.UDP_Socket,
	stop:   bool,
	hits:   int,
	stray:  bool,
}

// Answers with an A record, and with an OPT record in the answer section
// beside it where `stray` is set.
@(private = "file")
opt_loop :: proc(m: ^Opt_Mock) {
	buf: [512]u8
	for !sync.atomic_load(&m.stop) {
		n, client, err := net.recv_udp(m.socket, buf[:])
		if err != nil || n < dns.HEADER_SIZE {
			continue
		}
		q, derr := dns.decode_message(buf[:n], context.temp_allocator)
		if derr != .None || len(q.question) != 1 {
			continue
		}
		sync.atomic_add(&m.hits, 1)
		answer := make([dynamic]dns.Record, context.temp_allocator)
		append(&answer, dns.Record{name = q.question[0].name, type = .A, class = .IN, ttl = 300, data = dns.Rdata_A{addr = {192, 0, 2, 1}}})
		if m.stray {
			append(&answer, dns.make_opt(4096, false))
		}
		reply := dns.Message {
			id       = q.id,
			question = q.question,
			answer   = answer[:],
		}
		reply.flags.qr = true
		reply.flags.rd = q.flags.rd
		reply.flags.ra = true
		wire, _, _ := dns.encode_message(reply, context.temp_allocator)
		_, _ = net.send_udp(m.socket, wire, client)
		free_all(context.temp_allocator)
	}
}

@(private = "file")
start_mock :: proc(t: ^testing.T, m: ^Opt_Mock, name: string) -> (^Upstream, ^thread.Thread, bool) {
	socket, serr := net.make_bound_udp_socket(net.IP4_Loopback, 0)
	if !testing.expectf(t, serr == nil, "bind: %v", serr) {
		return nil, nil, false
	}
	m.socket = socket
	set_socket_timeouts(socket, 50 * time.Millisecond)
	bound, berr := net.bound_endpoint(socket)
	if !testing.expectf(t, berr == nil, "cannot read the responder's port: %v", berr) {
		net.close(socket)
		return nil, nil, false
	}
	u, uerr := make_upstream(
		config.Upstream_Spec{name = name, kind = .UDP, address = "127.0.0.1", port = bound.port},
		0,
		time.Second,
		context.allocator,
	)
	if !testing.expectf(t, uerr == .None, "upstream: %v", uerr) {
		net.close(socket)
		return nil, nil, false
	}
	return u, thread.create_and_start_with_poly_data(m, opt_loop), true
}

@(test)
test_a_stray_opt_record_is_swept_past :: proc(t: ^testing.T) {
	stray := Opt_Mock {
		stray = true,
	}
	plain: Opt_Mock
	// Neither started means neither closed: a zero socket here is fd 0, which
	// under `odin test` is another test's.
	bad, bad_thread, bad_ok := start_mock(t, &stray, "stray")
	if !bad_ok {
		return
	}
	good, good_thread, good_ok := start_mock(t, &plain, "plain")
	if !good_ok {
		sync.atomic_store(&stray.stop, true)
		thread.join(bad_thread)
		thread.destroy(bad_thread)
		net.close(stray.socket)
		destroy(bad)
		return
	}
	defer {
		sync.atomic_store(&stray.stop, true)
		sync.atomic_store(&plain.stop, true)
		thread.join(bad_thread)
		thread.join(good_thread)
		thread.destroy(bad_thread)
		thread.destroy(good_thread)
		net.close(stray.socket)
		net.close(plain.socket)
		destroy(bad)
		destroy(good)
	}

	g := Group {
		servers   = []^Upstream{bad, good},
		strategy  = .Failover,
		timeout   = time.Second,
		attempts  = 1,
		allocator = context.allocator,
	}
	query := dns.Message{id = 0x3530, question = []dns.Question{{name = "www.example.com.", type = .A, class = .IN}}}
	query.flags.rd = true
	wire, _, _ := dns.encode_message(query, context.temp_allocator)

	// A client's own question.
	resp, winner, err := resolve_readable(&g, wire, context.allocator)
	testing.expect_value(t, err, Error.None)
	testing.expect(t, winner == good, "resolve_readable took the reply with the stray OPT record")
	testing.expect(t, !dns.peek_opt_unreadable(resp), "the reply handed back carries the stray OPT record")
	delete(resp, context.allocator)

	// The chain walk's sweep.
	chain, chain_winner, chain_err := resolve_answerable(&g, wire, context.allocator)
	testing.expect_value(t, chain_err, Error.None)
	testing.expect(t, chain_winner == good, "resolve_answerable took the reply with the stray OPT record")
	delete(chain, context.allocator)

	testing.expect(t, sync.atomic_load(&stray.hits) >= 2, "the stray member was not asked first each time")
	free_all(context.temp_allocator)
}
