package pool

import "base:runtime"
import "core:sys/posix"
import "core:thread"

/*
Start a thread that never takes the signals `main` acts on: SIGTERM, SIGINT and
SIGHUP (#416).

A handler only sets a flag, but the kernel hands a process-directed signal to
any thread that has it unblocked - the main thread first, another when the main
thread already has it pending. A thread that takes one in a timed socket read
has the read fail with EINTR, which signal(7) says is never restarted however
the handler was installed: a list download fails, or an upstream read and the
query behind it. Every thread is started here, so the main thread is the only
one that takes them.
*/
spawn :: proc(data: $T, fn: proc(data: T), init_context: Maybe(runtime.Context) = nil) -> ^thread.Thread {
	set, old: posix.sigset_t
	posix.sigemptyset(&set)
	for sig in ([]posix.Signal{.SIGTERM, .SIGINT, .SIGHUP}) {
		posix.sigaddset(&set, sig)
	}
	// The thread inherits the mask. One of these arriving meanwhile is held,
	// and delivered on the restore.
	posix.pthread_sigmask(.BLOCK, &set, &old)
	defer posix.pthread_sigmask(.SETMASK, &old, nil)
	return thread.create_and_start_with_poly_data(data, fn, init_context)
}
