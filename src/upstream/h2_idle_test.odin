package upstream

import "core:net"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:config"
import "elodin:h2"

/*
`close_idle` retires the shared HTTP/2 connection the way it does every other
transport's (#529): a connection the peer has closed, or one nobody has used
for the upstream's `idle_timeout`, or any one when `all` - but never one a
caller still holds, which is left to finish as a busy pipe is.

The connection is handed to the upstream the way `get_h2_conn` would, over
plain TCP to a listener that never accepts, as in h2_retire_test.odin.
*/
@(private = "file")
H2_Idle_Fixture :: struct {
	listener: net.TCP_Socket,
	u:        ^Upstream,
	hc:       ^H2_Conn,
	socket:   net.TCP_Socket,
	reader:   ^thread.Thread,
}

@(private = "file")
h2_idle_setup :: proc(t: ^testing.T, f: ^H2_Idle_Fixture) -> bool {
	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen: %v", lerr) {
		return false
	}
	f.listener = listener
	bound, _ := net.bound_endpoint(listener)
	u, uerr := make_upstream(
		config.Upstream_Spec{name = "h2idle", kind = .TCP, address = "127.0.0.1", port = bound.port, hostname = "doh.invalid", path = "/dns-query"},
		8,
		30 * time.Second,
	)
	if !testing.expectf(t, uerr == .None, "cannot make the upstream: %v", uerr) {
		net.close(listener)
		return false
	}
	f.u = u
	socket, derr := dial_tcp_timeout(bound, time.Second)
	if !testing.expectf(t, derr == .None, "cannot dial the listener: %v", derr) {
		h2_idle_teardown(f)
		return false
	}
	f.socket = socket
	_ = net.set_option(socket, .Receive_Timeout, H2_POLL_INTERVAL)
	sync.mutex_lock(&u.mu)
	u.proto = .H2
	f.hc = start_h2_conn(u, Stream{socket = socket})
	u.h2 = f.hc
	f.reader = u.h2_readers[len(u.h2_readers) - 1]
	sync.mutex_unlock(&u.mu)
	return true
}

@(private = "file")
h2_idle_teardown :: proc(f: ^H2_Idle_Fixture) {
	destroy(f.u)
	net.close(f.listener)
}

// Moves the last use back, as if the connection had sat unused that long.
@(private = "file")
h2_idle_age :: proc(hc: ^H2_Conn, by: time.Duration) {
	sync.mutex_lock(&hc.client.mu)
	hc.client.released = time.time_add(hc.client.released, -by)
	sync.mutex_unlock(&hc.client.mu)
}

@(private = "file")
h2_idle_kept :: proc(f: ^H2_Idle_Fixture) -> bool {
	sync.mutex_lock(&f.u.mu)
	defer sync.mutex_unlock(&f.u.mu)
	return f.u.h2 == f.hc
}

@(private = "file")
h2_idle_reader_left :: proc(t: ^testing.T, reader: ^thread.Thread) {
	start := time.tick_now()
	for !thread.is_done(reader) && time.tick_since(start) < 3 * time.Second {
		time.sleep(time.Millisecond)
	}
	testing.expect(t, thread.is_done(reader), "the retired connection's reader is still polling")
}

@(test)
test_close_idle_retires_an_h2_conn_the_peer_closed :: proc(t: ^testing.T) {
	f: H2_Idle_Fixture
	if !h2_idle_setup(t, &f) {
		return
	}
	defer h2_idle_teardown(&f)

	// The reader's way out when the peer hangs up.
	_ = net.shutdown(f.socket, .Receive)
	for !thread.is_done(f.reader) {
		time.sleep(time.Millisecond)
	}
	testing.expect(t, h2.client_closed(f.hc.client), "the premise: the client is closed")
	testing.expect(t, h2_idle_kept(&f), "the premise: the upstream still holds it")

	closed := close_idle(f.u)
	testing.expect_value(t, closed, 1)
	sync.mutex_lock(&f.u.mu)
	testing.expect(t, f.u.h2 == nil, "a closed h2 connection survived the sweep")
	testing.expect_value(t, len(f.u.h2_readers), 0)
	sync.mutex_unlock(&f.u.mu)
}

@(test)
test_close_idle_retires_an_h2_conn_idle_past_the_timeout :: proc(t: ^testing.T) {
	f: H2_Idle_Fixture
	if !h2_idle_setup(t, &f) {
		return
	}
	defer h2_idle_teardown(&f)

	// Just inside the timeout: kept.
	h2_idle_age(f.hc, f.u.idle_timeout - 5 * time.Second)
	testing.expect_value(t, close_idle(f.u), 0)
	testing.expect(t, h2_idle_kept(&f), "an h2 connection was retired before its idle timeout")

	h2_idle_age(f.hc, 5 * time.Second)
	testing.expect_value(t, close_idle(f.u), 1)
	testing.expect(t, !h2_idle_kept(&f), "an h2 connection idle past the timeout survived the sweep")
	h2_idle_reader_left(t, f.reader)
	// Reaped by the sweep after it, not only at the next dial.
	_ = close_idle(f.u)
	sync.mutex_lock(&f.u.mu)
	testing.expect_value(t, len(f.u.h2_readers), 0)
	sync.mutex_unlock(&f.u.mu)
}

@(test)
test_close_idle_leaves_an_h2_conn_in_use :: proc(t: ^testing.T) {
	f: H2_Idle_Fixture
	if !h2_idle_setup(t, &f) {
		return
	}
	defer h2_idle_teardown(&f)

	// What `get_h2_conn` hands a caller: a reference of its own. Last let go
	// of long ago, so only the reference keeps it.
	h2.client_ref(f.hc.client)
	h2_idle_age(f.hc, time.Hour)
	testing.expect_value(t, close_idle(f.u, all = true), 0)
	testing.expect(t, h2_idle_kept(&f), "an h2 connection in use was retired")
	testing.expect(t, !h2.client_closed(f.hc.client))

	// Letting go counts as a use: the idle time starts again from there.
	h2.client_unref(f.hc.client)
	testing.expect_value(t, close_idle(f.u), 0)
	testing.expect(t, h2_idle_kept(&f), "an h2 connection just let go of was retired")

	testing.expect_value(t, close_idle(f.u, all = true), 1)
	testing.expect(t, !h2_idle_kept(&f), "`all` left an idle h2 connection")
	h2_idle_reader_left(t, f.reader)
}
