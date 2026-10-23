package pool

import "base:runtime"
import "core:sync"
import "core:sys/linux"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"

/*
The running limit, read off the pool's own state rather than timed.

Each test holds its jobs on a gate and then looks at the pool under its lock:
how many workers are awake, how many idle, how many jobs nobody has taken. A
worker leaves `idle` only through `wake`, under that same lock, so what is seen
there is what the limit allowed and not a moment in a race. The waits are on
events; their timeouts only bound a failing run.
*/

@(private = "file")
WAIT :: 5 * time.Second

@(private = "file")
Gate :: struct {
	mu:      sync.Mutex,
	cond:    sync.Cond,
	open:    bool,
	entered: int,
	// Jobs that call `blocking_begin` before they wait, and how many deep.
	blocks:  int,
	done:    sync.Sema,
}

@(private = "file")
gate_job :: proc(data: rawptr) {
	g := cast(^Gate)data
	sync.mutex_lock(&g.mu)
	g.entered += 1
	sync.cond_broadcast(&g.cond)
	depth := g.blocks
	sync.mutex_unlock(&g.mu)

	for _ in 0 ..< depth {
		blocking_begin()
	}
	sync.mutex_lock(&g.mu)
	for !g.open {
		sync.cond_wait(&g.cond, &g.mu)
	}
	sync.mutex_unlock(&g.mu)
	for _ in 0 ..< depth {
		blocking_end()
	}
	sync.sema_post(&g.done)
}

// Wait for `n` jobs to have entered; false if they did not in time.
@(private = "file")
await_entered :: proc(g: ^Gate, n: int) -> bool {
	sync.mutex_lock(&g.mu)
	defer sync.mutex_unlock(&g.mu)
	start := time.tick_now()
	for g.entered < n {
		left := WAIT - time.tick_since(start)
		if left <= 0 {
			return false
		}
		_ = sync.cond_wait_with_timeout(&g.cond, &g.mu, left)
	}
	return true
}

@(private = "file")
gate_release :: proc(g: ^Gate, jobs: int) -> bool {
	sync.mutex_lock(&g.mu)
	g.open = true
	sync.cond_broadcast(&g.cond)
	sync.mutex_unlock(&g.mu)
	for _ in 0 ..< jobs {
		if !sync.sema_wait_with_timeout(&g.done, WAIT) {
			return false
		}
	}
	return true
}

@(private = "file")
State :: struct {
	active, idle, unclaimed: int,
}

@(private = "file")
state_of :: proc(p: ^Pool) -> State {
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)
	return {p.active, len(p.idle), len(p.queue) - p.head}
}

// Wait until every worker that is not running a job has parked, so a test
// starts from a pool whose workers have all finished starting.
@(private = "file")
await_idle :: proc(p: ^Pool, idle: int) -> bool {
	start := time.tick_now()
	for state_of(p).idle < idle {
		if time.tick_since(start) > WAIT {
			return false
		}
		time.sleep(time.Millisecond)
	}
	return true
}

// Jobs that never wait on anything but the CPU are run no more than `limit` at
// once, however many workers are idle.
@(test)
test_a_limited_pool_runs_no_more_than_its_limit :: proc(t: ^testing.T) {
	p := make_pool(8, limit = 2)
	defer destroy(p)
	testing.expect(t, await_idle(p, 8))

	g: Gate
	for _ in 0 ..< 6 {
		testing.expect(t, submit(p, gate_job, &g))
	}
	testing.expect(t, await_entered(&g, 2))
	testing.expect_value(t, state_of(p), State{active = 2, idle = 6, unclaimed = 4})

	testing.expect(t, gate_release(&g, 6))
	testing.expect_value(t, g.entered, 6)
}

/*
Jobs submitted before the workers have finished starting are held to the limit
too. A worker that has not yet parked must not take a job on its way to `idle`,
or the limit holds only for a pool that was idle when the burst arrived.
*/
@(test)
test_a_pool_still_starting_runs_no_more_than_its_limit :: proc(t: ^testing.T) {
	p := make_pool(8, limit = 1)
	defer destroy(p)

	g: Gate
	for _ in 0 ..< 8 {
		testing.expect(t, submit(p, gate_job, &g))
	}
	// Every worker either parked or running a job, which is when the count of
	// running ones can no longer change before the gate opens.
	start := time.tick_now()
	for {
		sync.mutex_lock(&g.mu)
		entered := g.entered
		sync.mutex_unlock(&g.mu)
		if entered + state_of(p).idle == 8 {
			testing.expect_value(t, entered, 1)
			break
		}
		if !testing.expect(t, time.tick_since(start) < WAIT, "the workers never settled") {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect(t, gate_release(&g, 8))
}

/*
A job submitted before any worker has parked still runs. There is nobody on
`idle` for the submit to wake, so it is the starting worker that has to look at
the queue. Repeated because whether the submit beats the threads' start is the
scheduler's to decide; it does on nearly every round.
*/
@(test)
test_a_job_submitted_while_the_pool_starts_runs :: proc(t: ^testing.T) {
	for limit in 0 ..= 1 {
		for _ in 0 ..< 50 {
			p := make_pool(2, limit = limit)
			who: Who
			testing.expect(t, submit(p, who_job, &who))
			ran := sync.sema_wait_with_timeout(&who.done, WAIT)
			testing.expect(t, ran, "a job submitted as the pool started never ran")
			destroy(p)
			if !ran {
				return
			}
		}
	}
}

// A worker waiting inside `blocking_begin` gives its slot to a queued job, and
// a nested pair is counted once.
@(test)
test_a_blocked_worker_hands_its_slot_on :: proc(t: ^testing.T) {
	p := make_pool(4, limit = 1)
	defer destroy(p)
	testing.expect(t, await_idle(p, 4))

	blocked := Gate{blocks = 2}
	testing.expect(t, submit(p, gate_job, &blocked))
	testing.expect(t, await_entered(&blocked, 1))

	// Two more, which a single slot would run one after the other: the first
	// takes the slot the blocked worker gave up, the second waits for it.
	busy: Gate
	testing.expect(t, submit(p, gate_job, &busy))
	testing.expect(t, submit(p, gate_job, &busy))
	testing.expect(t, await_entered(&busy, 1))
	testing.expect_value(t, state_of(p), State{active = 1, idle = 2, unclaimed = 1})

	testing.expect(t, gate_release(&busy, 2))
	testing.expect(t, gate_release(&blocked, 1))
}

/*
A worker back from a block runs past the limit only until its own job ends. With
jobs still queued it parks rather than taking the next, or a backlog that never
drains would leave every worker an upstream reply brought back running.
*/
@(test)
test_a_worker_back_from_a_block_over_the_limit_parks :: proc(t: ^testing.T) {
	p := make_pool(4, limit = 1)
	defer destroy(p)
	testing.expect(t, await_idle(p, 4))

	blocked := Gate{blocks = 1}
	testing.expect(t, submit(p, gate_job, &blocked))
	testing.expect(t, await_entered(&blocked, 1))
	busy: Gate
	for _ in 0 ..< 3 {
		testing.expect(t, submit(p, gate_job, &busy))
	}
	testing.expect(t, await_entered(&busy, 1))

	// Back from its block with the slot taken, and two jobs queued behind it.
	testing.expect(t, gate_release(&blocked, 1))
	start := time.tick_now()
	for {
		sync.mutex_lock(&busy.mu)
		entered := busy.entered
		sync.mutex_unlock(&busy.mu)
		if entered + state_of(p).idle == 4 {
			testing.expect_value(t, entered, 1)
			testing.expect_value(t, state_of(p), State{active = 1, idle = 3, unclaimed = 2})
			break
		}
		if !testing.expect(t, time.tick_since(start) < WAIT, "the workers never settled") {
			break
		}
		time.sleep(time.Millisecond)
	}
	testing.expect(t, gate_release(&busy, 3))
}

// Off a worker thread the calls are no-ops, so code that runs on a connection's
// thread as well as on the pool need not know which it is on.
@(test)
test_blocking_off_a_worker_changes_nothing :: proc(t: ^testing.T) {
	p := make_pool(2, limit = 1)
	defer destroy(p)
	testing.expect(t, await_idle(p, 2))

	blocking_begin()
	testing.expect_value(t, state_of(p), State{active = 0, idle = 2})
	blocking_end()
	testing.expect_value(t, state_of(p), State{active = 0, idle = 2})
}

@(private = "file")
Who :: struct {
	worker: ^Worker,
	done:   sync.Sema,
}

@(private = "file")
who_job :: proc(data: rawptr) {
	w := cast(^Who)data
	w.worker = current
	sync.sema_post(&w.done)
}

// Jobs one at a time land on the worker that went idle last, not on each
// worker in turn.
@(test)
test_an_idle_pool_reuses_its_warmest_worker :: proc(t: ^testing.T) {
	p := make_pool(4)
	defer destroy(p)
	testing.expect(t, await_idle(p, 4))

	first: ^Worker
	for i in 0 ..< 8 {
		who: Who
		testing.expect(t, submit(p, who_job, &who))
		testing.expect(t, sync.sema_wait_with_timeout(&who.done, WAIT))
		testing.expect(t, await_idle(p, 4))
		if i == 0 {
			first = who.worker
		}
		testing.expect(t, who.worker == first)
	}
}

@(private = "file")
Mask_Probe :: struct {
	blocked: [3]bool,
}

@(test)
test_a_spawned_thread_holds_the_signals_main_acts_on :: proc(t: ^testing.T) {
	// See `spawn`: a thread that took one in a timed read would fail the read.
	before: Mask_Probe
	read_mask(&before)
	probe: Mask_Probe
	th := spawn(&probe, read_mask)
	if !testing.expect(t, th != nil, "no thread") {
		return
	}
	thread.join(th)
	thread.destroy(th)
	testing.expect_value(t, probe.blocked, [3]bool{true, true, true})

	// And the caller's own mask is put back as it was.
	after: Mask_Probe
	read_mask(&after)
	testing.expect_value(t, after.blocked, before.blocked)
}

@(private = "file")
read_mask :: proc(p: ^Mask_Probe) {
	cur: posix.sigset_t
	posix.pthread_sigmask(.BLOCK, nil, &cur)
	for sig, i in ([]posix.Signal{.SIGTERM, .SIGINT, .SIGHUP}) {
		p.blocked[i] = posix.sigismember(&cur, sig) == 1
	}
}

@(private = "file")
Scratch_Probe :: struct {
	// What the thread found its arena backed by, before it allocated.
	backed:   bool,
	// The arena's first block, and a second one a request past it took.
	blocks:   [2][]u8,
	resident: [2]int,
	// Blocks taken from and given back to `mapped_allocator`, counted by
	// `counting_proc`; the thread's exit is what gives them back.
	allocs:   int,
	frees:    int,
}

/*
See `run_with_mapped_scratch`: a thread's scratch blocks are mappings of their
own, resident as far as they are used, and given back once the thread exits -
for a thread started with a context (a rebuild) as much as without one (a
connection). Residency is read with mincore(2) while the block is live; the
release is counted rather than read off the address afterwards, which another
test's thread may have mapped again by then.
*/
@(test)
test_a_spawned_threads_scratch_is_unmapped_when_it_exits :: proc(t: ^testing.T) {
	for with_context in ([]bool{false, true}) {
		probe: Scratch_Probe
		th := spawn(&probe, use_scratch, context) if with_context else spawn(&probe, use_scratch)
		if !testing.expect(t, th != nil, "no thread") {
			return
		}
		thread.join(th)
		thread.destroy(th)
		if !testing.expectf(t, probe.backed, "the arena was not backed by mapped_allocator (context %v)", with_context) {
			continue
		}
		for b, i in probe.blocks {
			if !testing.expectf(t, len(b) > 0, "block %d was not seen (context %v)", i, with_context) {
				return
			}
			// A calloc'd block is resident throughout; this one, where touched.
			testing.expectf(t, probe.resident[i] <= 2, "block %d: %d pages resident of %d (context %v)", i, probe.resident[i], len(b) / PAGE, with_context)
		}
		testing.expectf(t, probe.allocs == 2 && probe.frees == 2, "%d blocks mapped, %d given back (context %v)", probe.allocs, probe.frees, with_context)
	}
}

@(private = "file")
PAGE :: 4096

@(private = "file")
use_scratch :: proc(p: ^Scratch_Probe) {
	arena := &runtime.global_default_temp_allocator_data.arena
	p.backed = arena.curr_block == nil && arena.backing_allocator.procedure == mapped_allocator_proc
	if !p.backed {
		return
	}
	arena.backing_allocator = runtime.Allocator{counting_proc, p}
	_ = make([]u8, 64, context.temp_allocator)
	first := arena.curr_block
	// Past the first block, so the arena takes a second.
	_ = make([]u8, runtime.DEFAULT_TEMP_ALLOCATOR_BACKING_SIZE + 1, context.temp_allocator)
	for b, i in ([]^runtime.Memory_Block{first, arena.curr_block}) {
		if b == nil || (i == 1 && b == first) {
			return
		}
		p.blocks[i] = b.base[:b.capacity]
		p.resident[i], _ = residency(p.blocks[i])
	}
}

// `mapped_allocator`, counting into the probe what it maps and gives back.
@(private = "file")
counting_proc :: proc(
	data: rawptr,
	mode: runtime.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	runtime.Allocator_Error,
) {
	p := (^Scratch_Probe)(data)
	b, err := mapped_allocator_proc(nil, mode, size, alignment, old_memory, old_size, loc)
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		p.allocs += 1 if err == nil else 0
	case .Free:
		p.frees += 1
	}
	return b, err
}

// Pages of `b` resident, by mincore(2) over the pages it spans.
@(private = "file")
residency :: proc(b: []u8) -> (pages: int, err: linux.Errno) {
	start := uintptr(raw_data(b)) &~ (PAGE - 1)
	end := (uintptr(raw_data(b)) + uintptr(len(b)) + PAGE - 1) &~ (PAGE - 1)
	vec := make([]b8, (end - start) / PAGE)
	defer delete(vec)
	err = linux.mincore(rawptr(start), uint(end - start), vec)
	for r in vec {
		pages += int(transmute(u8)r & 1)
	}
	return
}

/*
`mapped_allocator` hands out zeroed memory aligned as asked, and refuses an
alignment past a page rather than return a pointer that is not aligned to it.
*/
@(test)
test_mapped_allocator_aligns_and_zeroes :: proc(t: ^testing.T) {
	for align in ([]int{16, 64, PAGE}) {
		b, err := runtime.mem_alloc(10_000, align, mapped_allocator)
		if !testing.expectf(t, err == nil && len(b) == 10_000, "align %d: %v", align, err) {
			return
		}
		testing.expectf(t, uintptr(raw_data(b)) % uintptr(align) == 0, "align %d: %p", align, raw_data(b))
		zero := true
		for c in b {
			zero &&= c == 0
		}
		testing.expectf(t, zero, "align %d: not zeroed", align)
		b[len(b) - 1] = 1
		testing.expect_value(t, runtime.mem_free(raw_data(b), mapped_allocator), nil)
	}
	_, err := runtime.mem_alloc(64, 2 * PAGE, mapped_allocator)
	testing.expect_value(t, err, runtime.Allocator_Error.Invalid_Argument)
}
