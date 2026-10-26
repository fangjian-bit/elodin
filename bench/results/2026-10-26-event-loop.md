# The event loop against the thread model and Unbound

Measured on a 4-core arm64 VM (7.7 GiB, Linux 7.0.0-38-generic), the server
under test and the generator sharing it. Three servers, the same harness
configuration for each:

- **before**: elodin dev-8e947cd, the thread model (`origin/main` when #547 was cut);
- **after**: elodin dev-846ee95, the event loop;
- **Unbound 1.24.2**, forwarding to the same mock (`unboundConfig` in
  `cmd/bench/server.go` maps each setting).

Mock upstream at 20 ms unless a row says otherwise. DNSSEC off. Each run 10 s
measured after 2 s of warmup, median of 3. Taken a section at a time with
`go run ./cmd/bench -only <section>`, the before rows with `-binary` and
`-held 5000`.

The mock's own answer time wanders between 20 and 45 ms on this machine (timed
with `dig` against it alone), so miss rows taken at a different minute differ by
more than the servers do. The workloads table's "sustained cache misses" row is
the case: 4,375 before and 3,073 after in the matrix, 3,483 and 3,568 when the
two were run back to back on one mock.

## Cache misses against the upstream delay

2,000 clients over UDP, every name unique, `max_pending` 4096.

| server | upstream delay | cache misses | p50 | p99 | timed out |
|---|---|---|---|---|---|
| before | 20 ms | 3,536 qps | 569.9 ms | 733.1 ms | 0 |
| after | 20 ms | 83,831 qps | 22.9 ms | 33.4 ms | 0 |
| Unbound | 20 ms | 41,566 qps | 22.0 ms | 47.0 ms | 1,885 |
| before | 5 ms | 21,830 qps | 89.5 ms | 134.6 ms | 0 |
| after | 5 ms | 53,680 qps | 35.4 ms | 71.8 ms | 0 |
| Unbound | 5 ms | 63,447 qps | 9.6 ms | 18.2 ms | 3,080 |

At 20 ms the thread model is its 128 workers over the delay; the event loop is
24 times that and twice Unbound. At 5 ms the event loop is out of CPU first: the
p50 is queueing in the loops, where Unbound answers in two round trips.

## Event loops on two cores

Server pinned to CPUs 0-1, generator to 2-3, 1,000 clients over UDP,
`max_pending` 4096. Loops are `listeners.udp.readers` (Unbound: `num-threads`);
for the thread model the figure is only its UDP reader count.

| server | loops | cache misses | miss p99 | cache hits | hit p99 |
|---|---|---|---|---|---|
| before | 1 | 3,078 qps | 399.2 ms | 490,748 qps | 4.9 ms |
| before | 2 | 3,140 qps | 443.8 ms | 494,322 qps | 5.2 ms |
| before | 4 | 3,086 qps | 426.5 ms | 478,804 qps | 5.4 ms |
| after | 1 | 35,807 qps | 32.7 ms | 289,699 qps | 4.3 ms |
| after | 2 | 44,690 qps | 35.6 ms | 563,433 qps | 4.7 ms |
| after | 4 | 45,290 qps | 41.4 ms | 559,215 qps | 6.4 ms |
| Unbound | 1 | 3,037 qps | 94.4 ms | 334,217 qps | 3.3 ms |
| Unbound | 2 | 8,176 qps | 79.4 ms | 395,747 qps | 2.8 ms |
| Unbound | 4 | 22,637 qps | 65.7 ms | 390,954 qps | 4.1 ms |

Loops past the cores add nothing, which is why the derived count is the cores.
One loop answers fewer hits than the thread model's pool did on two cores; two
answer more.

## Memory per query in flight

Upstream answering after 3 s, every name unique, cache off, `max_pending`
N + 256. (peak RSS − idle RSS) ÷ N.

| server | in flight | answered | idle RSS | peak RSS | per query |
|---|---|---|---|---|---|
| before | 1,000 | 128 of 1,000 | 13 MB | 15 MB | — |
| after | 1,000 | all | 10 MB | 27 MB | 17 KB |
| after | 3,000 | all | 10 MB | 59 MB | 17 KB |
| Unbound | 1,000 | all | 171 MB | 184 MB | 13 KB |
| Unbound | 3,000 | all | 172 MB | 218 MB | 16 KB |

The thread model holds as many as it has workers and queues the rest past the
generator's five-second wait. Unbound's idle figure is its preallocated buffers
and caches at this configuration.

## Memory per idle connection

Each client asks one cached name and holds its connection idle.
(RSS held − RSS before) ÷ N. Unbound's rows stop at 5,000: it allocates a
64 KiB buffer per configured TCP handler at start, which is its "RSS before"
here, and 20,000 is several GiB before a client connects.

| server | transport | 1,000 | 5,000 | 20,000 |
|---|---|---|---|---|
| before | TCP | 25 KB | 25 KB | — |
| after | TCP | 21 KB | 21 KB | 21 KB |
| Unbound | TCP | 0.2 KB (276 MB before) | 0.1 KB (1,038 MB before) | — |
| before | DoT | 95 KB | 93 KB | — |
| after | DoT | 74 KB | 72 KB | 72 KB |
| Unbound | DoT | 56 KB | 54 KB | — |
| before | DoH/2 | 94 KB | 91 KB | — |
| after | DoH/2 | 72 KB | 71 KB | 70 KB |
| Unbound | DoH/2 | 70 KB | 68 KB | — |

20,000 held DoT connections on the event loop are 1.4 GB, OpenSSL's session
being most of it, on five threads.

## Cache hits

100 clients each holding its connection, every answer from the cache, every core.

| server | transport | throughput | p50 | p99 | CPU per query |
|---|---|---|---|---|---|
| before | UDP | 394,747 qps | 0.15 ms | 2.0 ms | 6 µs |
| after | UDP | 506,996 qps | 0.10 ms | 1.4 ms | 4 µs |
| Unbound | UDP | 704,506 qps | 0.05 ms | 2.3 ms | 2 µs |
| before | TCP | 210,927 qps | 0.09 ms | 4.5 ms | 11 µs |
| after | TCP | 361,818 qps | 0.17 ms | 2.1 ms | 7 µs |
| Unbound | TCP | 447,544 qps | 0.11 ms | 1.4 ms | 5 µs |

CPU per query on the other transports (`-only cpu`):

| server | DoT | DoH/1.1 | DoH/2 |
|---|---|---|---|
| before | 14 µs | 14 µs | 29 µs |
| after | 9 µs | 12 µs | 16 µs |
| Unbound | 7 µs | — (HTTP/2 only) | 13 µs |

This is the gap left: a cache hit costs about 1.5–2× Unbound's CPU. It is the
work done per query, not waiting, so it is not what the event loop changed.

## Past capacity

Cache misses from 6,000 clients at once, 20 ms upstream.

| server | max_pending | served | p50 | p99 | dropped |
|---|---|---|---|---|---|
| before | 1,024 | 3,242 qps | 270.7 ms | 398.8 ms | 24,903 |
| before | 8,192 | 3,218 qps | 1,791.5 ms | 1,950.5 ms | 0 |
| after | 1,024 | 39,943 qps | 21.4 ms | 35.7 ms | 24,880 |
| after | 8,192 | 45,111 qps | 120.4 ms | 231.3 ms | 0 |

For the thread model `max_pending` is the queue behind the workers; on the
event loop it is the queries in flight, so the bound is the throughput.

## Idle and steady state

| | before | after |
|---|---|---|
| idle, no lists | 13 MB | 10 MB |
| under load with 250,000 rules and the cache full | 119 MB | 104 MB |
| threads, idle | ~200 | 5 |
