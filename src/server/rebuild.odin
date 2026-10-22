package server

import "base:runtime"
import "core:sync"
import "core:thread"
import "elodin:pool"

/*
A rebuild of the rule sets, on a thread of its own (#416).

A rebuild downloads each list that is due, each for up to `FETCH_DEADLINE`. On
the maintenance thread, where signals are acted on and housekeeping runs, that
would hold a SIGTERM past an init system's stop timeout, which then kills the
process undrained; and a signal the kernel handed that thread would cut the
download it is in short, as a failed one. So the loop starts a rebuild here and
goes on. One runs at a time, under the generation it pinned; a reload meanwhile
goes ahead, and the rebuild it asks for follows.

Like every thread, it starts with the signals `main` acts on blocked, so the
kernel hands them to a thread that is not downloading; see `pool.spawn`.
*/
Rebuild :: struct {
	s:       ^Server,
	network: bool,
	thread:  ^thread.Thread,
	// Set once `current` is, when the rebuild is over.
	done:    bool,
	current: bool,
}

// Start a rebuild; the caller has checked none is running. False when no
// thread can be had, and nothing is started: run on the caller's thread, it
// would hold the signals that thread acts on.
rebuild_start :: proc(r: ^Rebuild, s: ^Server, network: bool) -> (started: bool) {
	// A second start would overwrite what the running thread still writes to.
	assert(!rebuild_busy(r), "a rebuild is already running")
	r^ = Rebuild {
		s       = s,
		network = network,
	}
	// The caller's allocators, as the sets and `lists_loaded` built there are
	// freed by the caller's thread; `thread` gives it a temp allocator of its own.
	r.thread = pool.spawn(r, rebuild_thread, context)
	if r.thread == nil {
		r^ = {}
		return false
	}
	return true
}

@(private = "file")
rebuild_thread :: proc(r: ^Rebuild) {
	r.current = rebuild_rules(r.s, r.network)
	sync.atomic_store(&r.done, true)
	// Handed a context, `thread` leaves its temp allocator to the thread.
	if context.temp_allocator.procedure == runtime.default_temp_allocator_proc {
		runtime.default_temp_allocator_destroy(auto_cast context.temp_allocator.data)
	}
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
	// `done` is set only by a thread `rebuild_start` started.
	thread.join(r.thread)
	thread.destroy(r.thread)
	current = r.current
	r^ = {}
	return current, true
}
