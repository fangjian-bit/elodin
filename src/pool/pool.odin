package pool

import "core:mem"
import "core:sync"
import "core:thread"
import "elodin:loop"

/*
A fixed-size worker pool over a FIFO job queue.

The server runs two of these. Query handling gets one; racing upstreams gets a
second, separate one. Keeping them apart matters: a race job is submitted *by* a
handler and waited on by it, so sharing a single pool could deadlock once every
worker is blocked waiting for jobs that no one is left to run.

Not `core:thread`'s `Pool`, which has no bounded submit: `pool_add_task` always
queues, where the listeners shed at `try_submit`'s limit rather than queue a
flood. It also appends every finished task to a `tasks_done` list that grows
until someone pops it, which a server that never does would hold forever.

**Two sizes, for the two things a handler does.** A cache miss holds its worker
for an upstream round trip, so the pool needs about as many workers as misses
in flight: thousands a second at a 20 ms upstream is a hundred threads. A cache
hit is tens of microseconds of CPU, and a hundred threads all runnable on two
cores answer fewer hits than a few do, since every job then wakes a thread of
its own instead of a busy worker taking the next job off the queue. So
`make_pool` takes both: `workers` threads, of which at most `limit` are woken
for work at once, where a worker inside `blocking_begin`/`blocking_end` (an
upstream round trip, a wait on another query's answer) is not counted. This is
the shape of Go's scheduler, where a goroutine entering a blocking call hands
its processor to another: the miss capacity of the large pool at the hit rate
of the small one.
*/

Job :: struct {
	fn:   proc(data: rawptr),
	data: rawptr,
}

/*
One worker's wake-up, so the pool chooses which worker it wakes: the one that
went idle last, rather than whichever the futex queue holds longest. Under light
load the work stays on the few threads that are warm, and a worker never woken
never touches its scratch arena.
*/
@(private)
Worker :: struct {
	pool:   ^Pool,
	cond:   sync.Cond,
	woken:  bool,
	// Nesting of `blocking_begin`; only the outermost pair is counted.
	blocks: int,
}

Pool :: struct {
	mu:        sync.Mutex,
	queue:     [dynamic]Job,
	head:      int,
	threads:   []^thread.Thread,
	workers:   []Worker,
	// Workers waiting for a job, the one that went idle last on top. Allocated
	// at its full size up front, so waiting never allocates.
	idle:      [dynamic]^Worker,
	// Workers awake and not inside `blocking_begin`, and the most `wake` brings
	// that to; a `limit` of zero is none. A worker coming back from a block is
	// not held to it, so `active` can run over until that worker's job ends.
	active:    int,
	limit:     int,
	running:   bool,
	allocator: mem.Allocator,
	pending:   int,
}

// The worker this thread is, if it is one, for `blocking_begin`.
@(private, thread_local)
current: ^Worker

make_pool :: proc(workers: int, limit := 0, allocator := context.allocator) -> ^Pool {
	p := new(Pool, allocator)
	p.allocator = allocator
	p.queue = make([dynamic]Job, 0, 64, allocator)
	p.running = true
	n := max(workers, 1)
	// A limit as wide as the pool can never bind, and as zero it spares every
	// `blocking_begin`/`blocking_end` pair two trips through `mu`.
	p.limit = limit if 0 < limit && limit < n else 0
	p.threads = make([]^thread.Thread, n, allocator)
	p.workers = make([]Worker, n, allocator)
	p.idle = make([dynamic]^Worker, 0, n, allocator)

	for i in 0 ..< n {
		p.workers[i].pool = p
		p.threads[i] = loop.spawn_thread(&p.workers[i], worker_loop)
	}
	return p
}

@(private)
worker_loop :: proc(w: ^Worker) {
	p := w.pool
	current = w
	sync.mutex_lock(&p.mu)
	// Not counted until it takes a job, so a worker still starting is held
	// to the limit like any other.
	park(p, w)
	for {
		if p.head >= len(p.queue) {
			if !p.running {
				sync.mutex_unlock(&p.mu)
				return
			}
			p.active -= 1
			park(p, w)
			continue
		}
		job := p.queue[p.head]
		p.head += 1
		// Reclaim the consumed prefix once it dominates the buffer.
		if p.head > 64 && p.head * 2 > len(p.queue) {
			remaining := len(p.queue) - p.head
			copy(p.queue[:remaining], p.queue[p.head:])
			resize(&p.queue, remaining)
			p.head = 0
		}
		sync.mutex_unlock(&p.mu)

		job.fn(job.data)

		sync.mutex_lock(&p.mu)
		p.pending -= 1
		// Back from a block past the limit: the job it already had was not held
		// to it, the next one is. Otherwise a backlog that never drains keeps
		// every worker that comes back from an upstream running, and the limit
		// is gone exactly when the load is highest.
		if p.running && p.limit > 0 && p.active > p.limit {
			p.active -= 1
			park(p, w)
		}
	}
}

/*
Wait on `idle` until woken, unless a job is already queued that the limit lets
this worker take. Under `p.mu`.

The queued job is the case of a worker still starting: a submit that found
nobody on `idle` woke nobody, and a worker that parked without looking would
leave the job queued until the next submit. After a job the caller has already
seen the queue empty, so there it only ever waits.

Only `wake` and `destroy` set `woken`, and both take the worker off `idle` as
they do, so a spurious wake-up waits again rather than leaving the worker
listed twice.
*/
@(private)
park :: proc(p: ^Pool, w: ^Worker) {
	if !p.running {
		return
	}
	if p.head < len(p.queue) && (p.limit == 0 || p.active < p.limit) {
		p.active += 1
		return
	}
	w.woken = false
	append(&p.idle, w)
	for !w.woken {
		sync.cond_wait(&w.cond, &p.mu)
	}
}

// Wake the worker that went idle last, if the limit allows one more. Under `p.mu`.
@(private)
wake :: proc(p: ^Pool) {
	if len(p.idle) == 0 || (p.limit > 0 && p.active >= p.limit) {
		return
	}
	w := pop(&p.idle)
	w.woken = true
	p.active += 1
	sync.cond_signal(&w.cond)
}

/*
The calling worker is about to wait on something other than the CPU, so another
may run in its place. A no-op on a thread that is not a worker of a limited pool
(a connection's thread, a racer), so a caller need not know where it runs.

Every wait a handler makes for longer than a lock hold goes inside one of these.
A wait left outside keeps its worker counted, and `limit` of those at once leave
the queue standing until one of them returns. The pairs nest.
*/
blocking_begin :: proc() {
	w := current
	if w == nil || w.pool.limit == 0 {
		return
	}
	w.blocks += 1
	if w.blocks > 1 {
		return
	}
	p := w.pool
	sync.mutex_lock(&p.mu)
	p.active -= 1
	if p.head < len(p.queue) {
		wake(p)
	}
	sync.mutex_unlock(&p.mu)
}

// The end of `blocking_begin`'s wait. Not held to the limit: the worker already
// has its job, and making it wait for a turn would be a second queue.
blocking_end :: proc() {
	w := current
	if w == nil || w.pool.limit == 0 {
		return
	}
	w.blocks -= 1
	if w.blocks > 0 {
		return
	}
	p := w.pool
	sync.mutex_lock(&p.mu)
	p.active += 1
	sync.mutex_unlock(&p.mu)
}

submit :: proc(p: ^Pool, fn: proc(data: rawptr), data: rawptr) -> bool {
	return try_submit(p, fn, data, 0) == .Accepted
}

Submit_Result :: enum {
	Accepted,
	// The backlog was already at `limit`.
	Full,
	// The pool is shutting down and takes no more work.
	Stopped,
}

/*
Submit unless the backlog is already at `limit`, deciding and appending under
one hold of the lock. A limit of zero or less is no limit.

Asking `pending` and then calling `submit` is not the same thing: the gap
between them is one every caller can pass through at once, and the callers are
not one thread. DoH over HTTP/2 runs a reader thread per connection, so a
synchronised burst can have `max_connections` of them each read a backlog one
short of the limit and each add to it - a queue past the limit by as many
threads as happened to be looking, which is the shape of load the limit is
there for.
*/
try_submit :: proc(p: ^Pool, fn: proc(data: rawptr), data: rawptr, limit: int) -> Submit_Result {
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)
	if !p.running {
		return .Stopped
	}
	if limit > 0 && p.pending >= limit {
		return .Full
	}
	append(&p.queue, Job{fn = fn, data = data})
	p.pending += 1
	wake(p)
	return .Accepted
}

// Jobs queued or in flight. Used to shed load before the queue grows unbounded.
pending :: proc(p: ^Pool) -> int {
	sync.mutex_lock(&p.mu)
	defer sync.mutex_unlock(&p.mu)
	return p.pending
}

worker_count :: proc(p: ^Pool) -> int {
	return len(p.threads)
}

// Stop accepting work, drain what is queued, and join every worker.
destroy :: proc(p: ^Pool) {
	if p == nil {
		return
	}
	sync.mutex_lock(&p.mu)
	p.running = false
	// Past the limit: draining is every worker's job now.
	for w in p.idle {
		w.woken = true
		sync.cond_signal(&w.cond)
	}
	clear(&p.idle)
	sync.mutex_unlock(&p.mu)

	for t in p.threads {
		thread.join(t)
		thread.destroy(t)
	}
	delete(p.threads, p.allocator)
	delete(p.workers, p.allocator)
	delete(p.idle)
	delete(p.queue)
	free(p, p.allocator)
}
