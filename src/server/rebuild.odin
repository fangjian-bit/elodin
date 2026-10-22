package server

import "base:runtime"
import "core:sync"
import "core:sys/posix"
import "core:thread"

/*
A rebuild of the rule sets, on a thread of its own (#416).

A rebuild downloads each list that is due, each for up to `FETCH_DEADLINE`. On
the maintenance thread, where signals are acted on and housekeeping runs, that
would hold a SIGTERM past an init system's stop timeout, which then kills the
process undrained; and a signal the kernel handed that thread would cut the
download it is in short, as a failed one. So the loop starts a rebuild here and
goes on. One runs at a time, and `reload_config`, which moves the history a
rebuild reads, waits for it.

The thread starts with the signals `main` acts on blocked - SIGTERM, SIGINT and
SIGHUP - so the kernel hands them to a thread that is not downloading.
*/
Rebuild :: struct {
	s:       ^Server,
	network: bool,
	thread:  ^thread.Thread,
	// Set once `current` is, when the rebuild is over.
	done:    bool,
	current: bool,
}

// Start a rebuild; the caller has checked none is running. With no thread to
// be had it runs on the caller's.
rebuild_start :: proc(r: ^Rebuild, s: ^Server, network: bool) {
	// A second start would overwrite what the running thread still writes to.
	assert(!rebuild_busy(r), "a rebuild is already running")
	r^ = Rebuild {
		s       = s,
		network = network,
	}
	set, old: posix.sigset_t
	posix.sigemptyset(&set)
	for sig in ([]posix.Signal{.SIGTERM, .SIGINT, .SIGHUP}) {
		posix.sigaddset(&set, sig)
	}
	// A signal that arrives meanwhile is held, and delivered on the restore.
	posix.pthread_sigmask(.BLOCK, &set, &old)
	// The caller's allocators, as the sets and `lists_loaded` built there are
	// freed by the caller's thread; `thread` gives it a temp allocator of its own.
	r.thread = thread.create_and_start_with_poly_data(r, rebuild_thread, context)
	posix.pthread_sigmask(.SETMASK, &old, nil)
	if r.thread == nil {
		rebuild_run(r)
	}
}

@(private = "file")
rebuild_thread :: proc(r: ^Rebuild) {
	rebuild_run(r)
	// Handed a context, `thread` leaves its temp allocator to the thread.
	if context.temp_allocator.procedure == runtime.default_temp_allocator_proc {
		runtime.default_temp_allocator_destroy(auto_cast context.temp_allocator.data)
	}
}

@(private = "file")
rebuild_run :: proc(r: ^Rebuild) {
	// The temp allocator is left alone: on the rebuild's thread it is destroyed
	// with the thread, and on the caller's it may hold what the caller still uses.
	r.current, _ = rebuild_rules(r.s, r.network)
	sync.atomic_store(&r.done, true)
}

// Started and not yet collected.
rebuild_busy :: proc(r: ^Rebuild) -> bool {
	return r.s != nil
}

// Over, and not yet collected.
rebuild_done :: proc(r: ^Rebuild) -> bool {
	return r.s != nil && sync.atomic_load(&r.done)
}

// A rebuild that is over, joined and forgotten; `over` is false while one runs,
// or when none was started.
rebuild_collect :: proc(r: ^Rebuild) -> (current, over: bool) {
	if !rebuild_done(r) {
		return
	}
	if r.thread != nil {
		thread.join(r.thread)
		thread.destroy(r.thread)
	}
	current = r.current
	r^ = {}
	return current, true
}
