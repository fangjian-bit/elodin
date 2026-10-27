Contributor details
Your Expensify account email: 3055073676@qq.com
Upwork Profile Link: https://www.upwork.com/freelancers/~01a6c3832b8108493d

## Proposal

### Please re-state the problem that we are trying to solve in this issue.

Currently, `elodin` processes incoming DNS queries using an OS thread-per-query and thread-per-connection concurrency model:
1. **Thread per in-flight query / shared pool**: A worker pool of up to 128 threads (`MAX_DERIVED_WORKERS :: 128` in `src/config/sizing.odin:47`) handles all UDP and DoH/2 queries, while an auxiliary racer pool (`race_pool` in `src/server/main.odin:745`) handles parallel upstream attempts. Every upstream round-trip, recursive chain-of-trust DNSSEC lookup, and in-flight query coalescing wait blocks the worker thread executing it.
2. **Thread per connection**: TCP, DoT, and DoH/1.1 connections dedicate one OS thread per connection (`server.max_connections :: 512` in `src/server/conns.odin`), where each thread allocates an OS stack, a 256 KiB scratch arena, and ~95 KB of OpenSSL session state for DoT.

This architecture enforces two rigid, hardware-independent performance bottlenecks:
- **In-flight cache misses are hard-capped by pool width**: At 20 ms upstream latency, 128 workers achieve a theoretical maximum of ~6,400 misses per second (and on memory-constrained systems like a 1 GiB host, `derive_workers` cuts the pool down to 42 workers). Real-world benchmarks show throughput capping at ~4,066 QPS on 2 cores (`bench/results/2026-10-16-pool-width.md`).
- **Concurrent open connections are hard-capped by thread count**: Capped at 512 connections (`server.max_connections`). Scaling worker threads exhausts memory due to per-thread scratch arenas and thread stacks, while idling connections hold OS threads hostage.

Unlike resolvers such as Unbound, Knot Resolver, and dnsdist—which multiplex tens of thousands of concurrent connections and in-flight queries over epoll on a handful of threads—`elodin` cannot handle high-load environments. The problem to solve is replacing the thread-per-query and thread-per-connection architecture with an event-driven, non-blocking Linux `epoll` event loop (one loop per core) featuring explicit continuation state machines, non-blocking TLS via OpenSSL memory BIOs, push-driven HTTP/2, and asynchronous completion-driven upstreams with robust memory lifetime management.

---

### What is the root cause of that problem?

The root cause stems from architectural coupling between network I/O wait points, OS threads, and thread-local scratch allocators across several core subsystems:

1. **Dual Thread-Model Dichotomy (`shared_worker` Flag)**:
   - In `src/server/resolver.odin:256`, `handle_query` requires `shared_worker := true` for UDP (`src/server/listeners.odin:1233`, `udp_job`) and DoH/2 (`src/server/doh2.odin`), delegating execution to `handler_pool` (`src/pool/pool.odin`).
   - Conversely, in `src/server/listeners.odin:1867` (`serve_dns_stream`) and `src/server/doh.odin:734` (`serve_doh_request`), `shared_worker = false` is passed, executing queries synchronously on connection threads spawned by `conn_spawn` (`src/server/conns.odin:113`).
   - This architectural split forces artificial bifurcations in configuration and sizing logic (`src/config/sizing.odin:245-256`), such as tracking `max_chain_walks` (96/128) vs. `max_connection_walks` (384/512) in `src/dnssec/validate.odin:204, 3412`, and asymmetric coalescing limits in `flight_join` (`src/server/inflight.odin`) and `refresh_ceiling` (`src/server/refresh.odin`).

2. **Synchronous Blocking Call Sites**:
   Network wait points park OS threads directly rather than suspending asynchronous execution:
   - **UDP Reader**: `listeners.odin:630` blocks on `net.recv_udp`.
   - **TCP Acceptor**: `listeners.odin:1537, 1576` blocks in `net.accept_tcp` and sleeps on backoff (`time.sleep(act.wait)`).
   - **Stream I/O & TLS**: `listeners.odin:1790-1990` blocks on `conn_read_full`/`conn_write_all`; `src/tlsx/tls.odin:700, 820, 876` polls on socket descriptors during `handshake_loop`, `transfer`, and `wait_ready`.
   - **HTTP/1.1 & HTTP/2**: `src/server/doh.odin:297, 962` synchronously reads HTTP requests; `src/h2/server.odin:328, 1717` runs blocking frame reader loops and conditions waits on flow control windows.
   - **Upstream Forwarding**: `src/upstream/upstream.odin:703` blocks inside `upstream.exchange` via `blocking_begin`/`blocking_end`; `src/upstream/group.odin:1088` blocks in `resolve_race` on semaphores; `src/upstream/pipeline.odin:482, 715, 1017` blocks on pipe slot condition variables; `src/upstream/h2client.odin:40, 147` locks a dedicated OS thread per upstream h2 connection.
   - **DNSSEC Validation**: `src/dnssec/validate.odin:3761, 4169` synchronously blocks on `v.query` callback execution during trust chain descent.
   - **Coalescing & Refresh**: `src/server/inflight.odin:239` parks followers via `flight_follow` condition variables; `src/server/refresh.odin:405` parks in `wait_refresh` on semaphores.

3. **Implicit Memory Lifecycle Bound to Thread Lifetime**:
   Across the query and server codebase, there are **197 non-test sites** referencing `context.temp_allocator` and **20 calls** to `free_all(context.temp_allocator)`. The existing code assumes that a thread scratch arena can simply be wiped clean whenever a thread finishes a job. Under an event loop where multiplexed queries interleave across event loop ticks, resetting `context.temp_allocator` at arbitrary points corrupts in-flight query states, causing fatal use-after-free bugs.

---

### What changes do you think we should make in order to solve the problem?

We propose implementing the non-blocking Linux `epoll` architecture across a single comprehensive pull request, divided internally into 10 structured, bisectable commits.

#### 1. Implement Thin Core Event Loop (`src/loop`)
Create a new standalone, Linux-native event loop package `src/loop` wrapping `core:sys/linux` epoll, timers, and eventfds:

```odin
package loop

import "core:sys/linux"
import "core:time"
import "core:mem"

Events :: distinct u32
EPOLL_IN  : Events : 0x001
EPOLL_OUT : Events : 0x004
EPOLL_ERR : Events : 0x008
EPOLL_HUP : Events : 0x010
EPOLL_RDHUP : Events : 0x2000

Watch :: struct {
    fd:       linux.Fd,
    on_event: proc(w: ^Watch, ev: Events),
    data:     rawptr,
    gen:      u64,
    active:   bool,
}

Timer :: struct {
    when:    time.Tick,
    on_fire: proc(t: ^Timer),
    data:    rawptr,
    armed:   bool,
    gen:     u64,
    index:   int, // Binary heap index
}

Post_Item :: struct {
    fn:   proc(data: rawptr),
    data: rawptr,
}

Loop :: struct {
    epfd:      linux.Fd,
    wakefd:    linux.Fd,
    running:   bool,
    cur_tick:  time.Tick,
    wake_w:    Watch,
    timers:    [dynamic]^Timer,
    post_mu:   mem.Mutex,
    post_q:    [dynamic]Post_Item,
    allocator: mem.Allocator,
}

make_loop :: proc(allocator := context.allocator) -> (^Loop, bool) {
    epfd, ep_err := linux.epoll_create1(linux.EPOLL_CLOEXEC)
    if ep_err != .NONE do return nil, false

    wakefd, w_err := linux.eventfd(0, linux.EFD_CLOEXEC | linux.EFD_NONBLOCK)
    if w_err != .NONE {
        linux.close(epfd)
        return nil, false
    }

    l := new(Loop, allocator)
    l.epfd = epfd
    l.wakefd = wakefd
    l.allocator = allocator
    l.running = true
    l.timers = make([dynamic]^Timer, allocator)
    l.post_q = make([dynamic]Post_Item, allocator)

    l.wake_w = Watch{
        fd = wakefd,
        on_event = proc(w: ^Watch, ev: Events) {
            val: u64
            linux.read(w.fd, &val, size_of(u64))
        },
        data = l,
    }
    watch(l, &l.wake_w, EPOLL_IN)
    return l, true
}

watch :: proc(l: ^Loop, w: ^Watch, events: Events) -> bool {
    w.gen += 1
    w.active = true
    ev := linux.Epoll_Event{
        events = u32(events),
        data   = linux.Epoll_Data{ptr = w},
    }
    ret := linux.epoll_ctl(l.epfd, .ADD, w.fd, &ev)
    return ret == .NONE
}

rearm :: proc(l: ^Loop, w: ^Watch, events: Events) -> bool {
    ev := linux.Epoll_Event{
        events = u32(events),
        data   = linux.Epoll_Data{ptr = w},
    }
    ret := linux.epoll_ctl(l.epfd, .MOD, w.fd, &ev)
    return ret == .NONE
}

unwatch :: proc(l: ^Loop, w: ^Watch) {
    if !w.active do return
    w.active = false
    w.gen += 1
    linux.epoll_ctl(l.epfd, .DEL, w.fd, nil)
}

arm :: proc(l: ^Loop, t: ^Timer, after: time.Duration) {
    t.gen += 1
    t.armed = true
    t.when = time.tick_add(now(l), after)
    heap_push(&l.timers, t)
}

disarm :: proc(l: ^Loop, t: ^Timer) {
    if !t.armed do return
    t.armed = false
    t.gen += 1
    heap_remove(&l.timers, t.index)
}

post :: proc(l: ^Loop, fn: proc(data: rawptr), data: rawptr) {
    mem.lock(&l.post_mu)
    append(&l.post_q, Post_Item{fn = fn, data = data})
    mem.unlock(&l.post_mu)
    val: u64 = 1
    linux.write(l.wakefd, &val, size_of(u64))
}

now :: proc(l: ^Loop) -> time.Tick {
    return l.cur_tick
}

run :: proc(l: ^Loop) {
    MAX_EVENTS :: 64
    events: [MAX_EVENTS]linux.Epoll_Event

    for l.running {
        l.cur_tick = time.tick_now()
        run_expired_timers(l)

        timeout_ms: i32 = -1
        if len(l.timers) > 0 {
            delta := time.tick_diff(l.cur_tick, l.timers[0].when)
            timeout_ms = max(i32(time.duration_milliseconds(delta)), 0)
        }

        n, _ := linux.epoll_wait(l.epfd, &events[0], MAX_EVENTS, timeout_ms)
        l.cur_tick = time.tick_now()

        for i in 0..<n {
            w := (^Watch)(events[i].data.ptr)
            ev := Events(events[i].events)
            cur_gen := w.gen
            if w.active && w.on_event != nil {
                w.on_event(w, ev)
            }
            // If watch was unwatched or replaced during callback, do not touch further
        }

        drain_posted(l)
    }
}
```

#### 2. Non-Blocking TLS via OpenSSL Memory BIOs (`src/tlsx`)
Eliminate socket blocking in TLS handshakes and I/O by decoupling OpenSSL from network sockets using memory BIO pairs (`BIO_s_mem`):
- Create `rbio := BIO_new(BIO_s_mem())` and `wbio := BIO_new(BIO_s_mem())`. Call `SSL_set_bio(ssl, rbio, wbio)`.
- During `EPOLLIN` on a TLS connection: read ciphertext from socket into a temporary buffer, write into `rbio` via `BIO_write`, then pump `SSL_do_handshake` or `SSL_read`.
- During `EPOLLOUT`: drain ciphertext from `wbio` via `BIO_read` and write to socket via `linux.write` or `linux.sendmmsg`. If `wbio` has pending bytes, arm `EPOLLOUT`; disarm once drained.
- BIO ownership: Transfer ownership to `SSL` immediately upon `SSL_set_bio`. On failure before `SSL_set_bio`, free BIOs directly; after `SSL_set_bio`, `SSL_free` cleans both BIOs automatically.

#### 3. Push-Driven HTTP/2 Engine (`src/h2/server.odin`, `src/h2/client.odin`)
- Replace the dedicated reader thread in `src/upstream/h2client.odin` and `src/h2/server.odin` with push-driven methods:
  - `feed(conn: ^H2_Conn, data: []byte) -> (consumed: int, err: Error)`
  - `pull(conn: ^H2_Conn) -> [][]byte`
- De-correlate stream flow control from thread condition variables: park stream continuation on `WINDOW_UPDATE` instead of `cond_wait`.
- Resize advertised `RECV_WINDOW` per connection from 1 MiB down to bounded buffer size (32 KiB) to prevent 10,000 idle connections from committing 10 GB of unbacked memory.

#### 4. Asynchronous Completion-Driven Upstreams (`src/upstream`)
- Replace the `race_pool` and blocking worker waits with an event-driven `Exchange`:
  ```odin
  Exchange :: struct {
      loop:        ^loop.Loop,
      id:          u16,
      timeout_tm:  loop.Timer,
      gen:         u64,
      on_complete: proc(ex: ^Exchange, res: ^dns.Message, err: Error),
      data:        rawptr,
      upstream:    ^Upstream,
      req_msg:     []byte,
  }
  ```
- **UDP**: Maintain one UDP socket per upstream per loop, registered in epoll. Allocate query IDs in a 16-bit table mapping `id -> ^Exchange`. When a datagram arrives on the upstream UDP socket, read via `recvmmsg`, parse header ID, look up `Exchange`, and resume continuation immediately.
- **TCP/DoT/DoH**: Multiplex queries over persistent, pipelined connections owned by the loop.
- **Racing & Fallback**: Implement query racing as N simultaneous `Exchange`s managed by a single timer. The first valid response disarms the timer and cancels competing exchanges; losing exchanges simply release state and do not charge false timeout errors to upstream health metrics.

#### 5. Per-Query Continuation State Machine (`src/server/resolver.odin`)
Convert synchronous `handle_query` and `resolve_query` into re-entrant step functions:

```odin
Query_State :: enum {
    Admitted,
    Rewriting,
    Local,
    Cache_Lookup,
    Waiting_Refresh,
    Following,
    Forwarding,
    Validating,
    Fetching_DS,
    Fetching_DNSKEY,
    Verifying,
    Storing,
    Answering,
    Done,
}

Query :: struct {
    loop:        ^loop.Loop,
    gen:         u64,
    arena:       virtual.Arena,
    spent:       int,
    state:       Query_State,
    origin:      union { Udp_Origin, ^Conn, ^H2_Stream, Refresh_Origin },
    msg:         dns.Message,
    cookie:      Cookie_Request,
    started:     time.Time,
    deadline:    time.Tick,
    flight:      ^Flight,
    exchange:    ^Exchange,
    walk:        dnssec.Walk,
    raw_packet:  []byte,
}

step_query :: proc(q: ^Query) {
    for {
        #partial switch q.state {
        case .Admitted:
            if !admit_query(q) {
                q.state = .Done
                finish_query(q)
                return
            }
            q.state = .Cache_Lookup

        case .Cache_Lookup:
            hit, verdict := cache_check(q)
            if hit {
                q.state = .Answering
            } else {
                q.state = .Forwarding
            }

        case .Forwarding:
            // Arms upstream exchange and parks
            start_upstream_exchange(q)
            return // Parked; loop will resume upon completion

        case .Answering:
            send_query_response(q)
            q.state = .Done

        case .Done:
            finish_query(q)
            return
        }
    }
}
```

#### 6. Memory Lifetime Management & Generation Protection
- **Eliminate `context.temp_allocator` on Query/Connection Paths**:
  - Replace with an explicit `virtual.Arena` per `Query` (initial 16 KiB block, dynamically growing, capped at `REQUEST_DECODE_BUDGET`). Freed exclusively in `finish_query`.
  - Introduce per-connection arenas for framing and buffer scratch.
  - Reset loop thread scratch allocator once per tick in `loop.run`.
  - Add a grep gate to `mise run check` forbidding unapproved `context.temp_allocator` invocations.
- **Generation Counters on All Asynchronous Callbacks**:
  - Every `Watch`, `Timer`, `Exchange`, and `Query` maintains a monotonic `gen: u64`.
  - When disarming, cancelling, or closing, increment `gen`. Upon callback dispatch, if `stored_gen != current_gen`, abort without accessing target memory.
- **File Descriptor Reuse Safeguard**:
  - Close socket descriptors only *after* calling `EPOLL_CTL_DEL` and nullifying the `Watch` pointer in active dispatch tables to prevent race conditions when the OS reallocates recycled file descriptors.

#### 7. Settings Deprecation & Sizing Modernization
- Deprecate `server.workers`, `server.running_workers`, `server.upstream_workers`, and `dnssec.max_connection_walks` gracefully: emit a diagnostic warning via `log.warn` during config parsing and `--check`, maintaining no-op compatibility for one release.
- Introduce `server.loops` (default: 0 = usable cores up to 8) and `server.max_inflight` (dynamically derived from system RAM via `WORKER_MEMORY_SHARE :: 32`).
- Update `main.odin:sizing_line` and documentation (`docs/sizing.md`, `docs/connections.md`, `docs/upstreams.md`).

---

### What alternative solutions did you explore? (Optional)

1. **`io_uring` Kernel Submission Queues**:
   - *Considered*: Linux `io_uring` offers batch completions and reduces syscall overhead for datagrams.
   - *Why Rejected*:
     - **Security bans**: Google disabled `io_uring` on ChromeOS, Android, and production clusters due to severe root privilege escalations; Linux 6.6+ provides `kernel.io_uring_disabled` which hardened hosts enable.
     - **Container restriction**: Default Docker/Moby seccomp profiles block `io_uring_setup`, `io_uring_enter`, and `io_uring_register`, breaking `examples/container.yaml`.
     - **Kernel requirements**: Advanced multishot recv and buffer rings (`IORING_REGISTER_PBUF_RING`) mandate Linux 6.0+, precluding Debian 12 (6.1) LTS or enterprise deployments.
     - **Toolchain limits**: Odin's `core:nbio` in the pinned toolchain lacks an epoll fallback on Linux.

2. **Scaling the Existing Worker Pool (e.g. 4096+ Threads)**:
   - *Considered*: Simply increasing `MAX_DERIVED_WORKERS` to 4096.
   - *Why Rejected*: Massively bloats memory footprint (thread stacks + per-worker scratch arenas would require gigabytes of RAM), increases glibc arena fragmentation, and overwhelms the kernel scheduler with thread context switches.

3. **Fiber / Coroutine Scheduling Runtime**:
   - *Considered*: Implementing lightweight userspace fibers with stack switching.
   - *Why Rejected*: Odin lacks language-level async/await primitives and green-thread runtime support. Userspace stack switching introduces stack-overflow vulnerabilities and complicates ASan and DWARF stack tracing. Explicit state-machine structs provide transparent, auditable memory footprints.

---

### What automated tests can you add to prevent this from re-occurring?

We can introduce comprehensive unit tests in `src/loop/loop_test.odin` and `src/server/resolver_test.odin`, verified under `mise run test` with `ODIN_TEST_FAIL_ON_BAD_MEMORY=true`:

```odin
package loop_test

import "core:testing"
import "core:time"
import "core:sys/linux"
import "core:net"
import "../loop"

// 1. Verify watch registration, level-triggering, rearm, and unwatch
@(test)
test_loop_watch_and_rearm :: proc(t: ^testing.T) {
    l, ok := loop.make_loop()
    testing.expect(t, ok, "Failed to create event loop")
    defer {
        linux.close(l.epfd)
        linux.close(l.wakefd)
        free(l)
    }

    fds: [2]linux.Fd
    linux.pipe2(&fds, linux.O_NONBLOCK | linux.O_CLOEXEC)
    defer { linux.close(fds[0]); linux.close(fds[1]) }

    received := false
    w := loop.Watch{
        fd = fds[0],
        on_event = proc(w: ^loop.Watch, ev: loop.Events) {
            rec := (^bool)(w.data)
            rec^ = true
            val: u8
            linux.read(w.fd, &val, 1)
        },
        data = &received,
    }

    loop.watch(l, &w, loop.EPOLL_IN)
    
    // Write a byte to pipe
    val: u8 = 42
    linux.write(fds[1], &val, 1)

    // Tick loop once
    l.cur_tick = time.tick_now()
    MAX_EV :: 4
    events: [MAX_EV]linux.Epoll_Event
    n, _ := linux.epoll_wait(l.epfd, &events[0], MAX_EV, 100)
    for i in 0..<n {
        ev_w := (^loop.Watch)(events[i].data.ptr)
        ev_w.on_event(ev_w, loop.Events(events[i].events))
    }

    testing.expect(t, received, "Watch failed to receive level-triggered EPOLLIN event")
    loop.unwatch(l, &w)
    testing.expect(t, !w.active, "Watch should be inactive after unwatch")
}

// 2. Verify timer ordering, firing, and generation invalidation upon disarm
@(test)
test_loop_timer_generation_cancellation :: proc(t: ^testing.T) {
    l, _ := loop.make_loop()
    defer {
        linux.close(l.epfd)
        linux.close(l.wakefd)
        free(l)
    }

    fired_a := false
    fired_b := false

    tm_a := loop.Timer{
        on_fire = proc(tm: ^loop.Timer) {
            b := (^bool)(tm.data)
            b^ = true
        },
        data = &fired_a,
    }
    tm_b := loop.Timer{
        on_fire = proc(tm: ^loop.Timer) {
            b := (^bool)(tm.data)
            b^ = true
        },
        data = &fired_b,
    }

    l.cur_tick = time.tick_now()
    loop.arm(l, &tm_a, 10 * time.Millisecond)
    loop.arm(l, &tm_b, 50 * time.Millisecond)

    // Cancel Timer A before it fires
    loop.disarm(l, &tm_a)

    // Advance clock past expiration
    l.cur_tick = time.tick_add(l.cur_tick, 60 * time.Millisecond)
    loop.run_expired_timers(l)

    testing.expect(t, !fired_a, "Cancelled timer must not fire (generation bump guard)")
    testing.expect(t, fired_b, "Uncancelled timer must fire when expired")
}

// 3. Verify cross-thread task posting via eventfd
@(test)
test_loop_post_cross_thread :: proc(t: ^testing.T) {
    l, _ := loop.make_loop()
    defer {
        linux.close(l.epfd)
        linux.close(l.wakefd)
        free(l)
    }

    called := false
    loop.post(l, proc(data: rawptr) {
        c := (^bool)(data)
        c^ = true
    }, &called)

    loop.drain_posted(l)
    testing.expect(t, called, "Posted procedure must execute cleanly during event loop drain")
}
```

Additionally, in `src/itest/cases_running.odin`, replace the existing `server.running_workers` test with an asynchronous concurrency test asserting that $N = 100$ concurrent queries against a mock upstream completing with 20 ms simulated latency resolve in approximately $\approx 20\text{ ms}$ on `loops: 1`, verifying that in-flight network waits overlap without parking execution threads.