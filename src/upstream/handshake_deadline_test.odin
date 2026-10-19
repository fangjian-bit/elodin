package upstream

import "core:net"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"
import "elodin:tlsx"

@(private = "file")
Stall_Mock :: struct {
	listener: net.TCP_Socket,
	reset_at: time.Duration,
	resets:   int,
	stalled:  int,
}

// Hangs up hard on the first caller just short of its budget, then accepts the
// retry and says nothing at all until the caller gives up and closes.
@(private = "file")
reset_then_stall :: proc(m: ^Stall_Mock) {
	first, _, ferr := net.accept_tcp(m.listener)
	if ferr != nil {
		return
	}
	time.sleep(m.reset_at)
	// SO_LINGER at zero makes close() a RST, which is the reset `open_stream`
	// retries; a FIN is a protocol error of OpenSSL's own and is not retried.
	lg := posix.linger {
		l_onoff  = 1,
		l_linger = 0,
	}
	posix.setsockopt(posix.FD(first), posix.SOL_SOCKET, .LINGER, &lg, posix.socklen_t(size_of(lg)))
	net.close(first)
	sync.atomic_add(&m.resets, 1)

	second, _, serr := net.accept_tcp(m.listener)
	if serr != nil {
		return
	}
	defer net.close(second)
	sync.atomic_add(&m.stalled, 1)
	_ = net.set_option(second, .Receive_Timeout, 3 * time.Second)
	buf: [512]u8
	for {
		n, rerr := net.recv_tcp(second, buf[:])
		if rerr != nil || n == 0 {
			return
		}
	}
}

/*
`open_stream` holds its caller to one deadline across both attempts, not to a
fresh `timeout` for each dial and each handshake (#346).

The peer resets the first handshake just short of the budget and never answers
the second. A retry given a fresh `timeout` would start a new second-long
handshake with the first one's time already spent and hold the caller for nearly
twice its budget - four times, with a dial slow to connect in front of each.
*/
@(test)
test_open_stream_spends_one_deadline_across_the_retry :: proc(t: ^testing.T) {
	posix.sigignore(.SIGPIPE)

	listener, lerr := net.listen_tcp(net.Endpoint{address = net.IP4_Loopback, port = 0})
	if !testing.expectf(t, lerr == nil, "cannot listen on loopback: %v", lerr) {
		return
	}
	defer net.close(listener)
	bound, berr := net.bound_endpoint(listener)
	if !testing.expectf(t, berr == nil, "cannot read the listener's port: %v", berr) {
		return
	}
	_ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)

	cctx, cerr := tlsx.client_context(false)
	if !testing.expectf(t, cerr == .None, "client_context: %v", cerr) {
		return
	}
	defer tlsx.context_destroy(cctx)

	BUDGET :: time.Second
	m := Stall_Mock {
		listener = listener,
		reset_at = 700 * time.Millisecond,
	}
	mock_thread := thread.create_and_start_with_poly_data(&m, reset_then_stall)

	start := time.tick_now()
	stream, oerr := open_stream(bound, cctx, "", BUDGET)
	spent := time.tick_since(start)
	if oerr == .None {
		stream_close(&stream)
	}
	thread.join(mock_thread)
	thread.destroy(mock_thread)

	// The premise: the first handshake was reset and a second one was made.
	testing.expect_value(t, sync.atomic_load(&m.resets), 1)
	testing.expect_value(t, sync.atomic_load(&m.stalled), 1)
	testing.expectf(t, oerr == .Timeout, "a stalled retry reported %v", oerr)
	// Above the budget by enough for a slow machine; below the 1.7s a fresh
	// `timeout` for the retry comes to.
	testing.expectf(t, spent < 1400 * time.Millisecond, "a %v open_stream was held for %v", time.Duration(BUDGET), spent)
	free_all(context.temp_allocator)
}

// One retry, from the first attempt, while the deadline has time left; with no
// deadline at all, always.
@(test)
test_open_stream_retries_only_inside_its_deadline :: proc(t: ^testing.T) {
	now := time.tick_now()
	ahead := time.tick_add(now, time.Second)
	behind := time.tick_add(now, -time.Second)
	testing.expect(t, retry_due(time.Second, ahead, now, 0), "no retry with a second left")
	testing.expect(t, !retry_due(time.Second, behind, now, 0), "a retry after the deadline")
	testing.expect(t, !retry_due(time.Second, ahead, now, 1), "a second retry")
	testing.expect(t, retry_due(0, behind, now, 0), "no retry under no deadline")
}

/*
A deadline already gone reaches the socket as a millisecond, not as a negative
`timeval` that reads back as zero - which the socket, and `tlsx` after it, take
as no timeout at all.
*/
@(test)
test_an_expired_deadline_is_a_millisecond_on_the_socket :: proc(t: ^testing.T) {
	socket, err := net.create_socket(.IP4, .TCP)
	if !testing.expectf(t, err == nil, "cannot make a socket: %v", err) {
		return
	}
	defer net.close(socket)
	set_socket_timeouts(socket, -5 * time.Millisecond)
	for option in ([]posix.Sock_Option{.RCVTIMEO, .SNDTIMEO}) {
		tv: posix.timeval
		length := posix.socklen_t(size_of(tv))
		got := posix.getsockopt(posix.FD(net.any_socket_to_socket(socket)), posix.SOL_SOCKET, option, &tv, &length)
		testing.expect_value(t, got, posix.result.OK)
		testing.expectf(t, tv.tv_sec == 0 && tv.tv_usec == 1000, "%v reads %ds %dus", option, tv.tv_sec, tv.tv_usec)
	}
}

// A positive timeout never reaches the socket as zero, which is no timeout at
// all: a deadline met exactly, or already gone, leaves a millisecond (#499).
@(test)
test_what_is_left_of_a_stream_deadline_is_never_zero :: proc(t: ^testing.T) {
	now := time.tick_now()
	testing.expect_value(t, stream_time_left(time.Second, now, now), time.Millisecond)
	testing.expect_value(t, stream_time_left(time.Second, time.tick_add(now, -time.Second), now), time.Millisecond)
	testing.expect_value(t, stream_time_left(time.Second, time.tick_add(now, 300 * time.Millisecond), now), 300 * time.Millisecond)
	testing.expect_value(t, stream_time_left(0, now, now), time.Duration(0))
}
