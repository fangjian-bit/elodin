# Sizing

Left unset (`0`, as the shipped configuration has them), the worker counts are
derived at startup from the machine:

```
workers           = 128, lowered if the threads that implies would take more
                    than 1/32 of usable memory (42 on a 1 GiB machine)
running_workers   = usable_cpus * 2, at most workers
upstream_workers  = workers / 2
max_pending       = workers * 8
```

- "Usable" is what this process can have: the CPU affinity mask, and a cgroup CPU
  or memory limit where there is one (`CPUQuota=`/`MemoryMax=` in a unit, or a
  container's limits).
- A number in the configuration always wins. The worker counts can be set
  independently; an unset `upstream_workers` follows a configured `workers`, and
  an unset `running_workers` is read off the CPUs whatever `workers` is.
- Where the CPUs could not be counted, `running_workers` is the whole pool: no
  limit.
- What it settled on is logged after startup and printed by `--check`:

```console
$ elodin --check
/etc/elodin/elodin.yaml is valid: 2 upstreams, 0 zone routes, 4 blocklists, 0 rewrites
  workers=128 running_workers=4 upstream_workers=64 max_pending=1024 chain_walks=96 connection_walks=384 (derived from 2 usable CPUs and 7.7 GiB)
  answering queries from 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, fc00::/7, fe80::/10; every other source is refused
  udp: 2 readers, asking for 1MiB of receive buffer each (derived from 2 usable CPUs)
  connections: at most 512 at once across TCP, DoT and DoH, of which one client prefix (/24, /64) may hold 256; connections past a prefix's share are refused and counted as conn_refused=
```

## Workers and running workers

A worker is held for the whole upstream round trip, so sustained cache-miss
throughput is roughly `server.workers / upstream_rtt`: the derived 128 against a
20 ms upstream is up to about 6,400 misses a second, on two cores as on thirty-two.

Only `running_workers` of them run at once. A worker waiting on an upstream, on
another client's identical query, or on a DoH client's flow-control window is
not counted, so the limit bounds the threads competing for the cores rather than
the queries in flight. The pool answers UDP and DoH over HTTP/2; TCP, DoT and
HTTP/1.1 answer on [their connection's own thread](#transports), which the limit
does not see. Cache hits are then answered by a worker already awake
instead of each waking one of its own. On two cores against a 20 ms mock
upstream, 128 clients over UDP
([`bench/results/2026-10-16-pool-width.md`](../bench/results/2026-10-16-pool-width.md),
`mise run bench -- -only sizing`):

| `workers` / `running_workers` | cache misses | cache hits |
|---|---|---|
| 16 / no limit | 493 qps | 435k qps |
| 128 / no limit | 3,794 qps | 208k qps |
| 128 / 4 (derived) | 4,066 qps | 360k qps |

Run-to-run spread on the hit rows is around ten percent; interleaved runs put
the first and last rows' hit rates within it of each other.

- **Every query shares the pool.** Running short of workers delays cache hits as
  much as misses, since a hit queues behind the misses holding every worker.
- **Raise `workers` for misses, not `running_workers`.** Measured at eight times
  the cores, the running limit buys contention, not throughput. Lowering it below the cores
  leaves a core idle.
- **Memory scales with the workers the load reaches.** Each worker keeps the
  pages of its 256 KiB scratch arena that its queries have touched, from its
  first query on, since Odin's temp allocator `free_all` keeps the first block.
  The pool wakes the worker that went idle last, so a resolver answering a few
  queries a second touches a few arenas; a burst that reaches all 128 leaves all
  128 resident.

Past `max_pending` queries are dropped, not queued: the client times out and
retries. A DoH client over HTTP/2 is answered `503` instead.

## Transports

- **UDP**: a reader thread per usable CPU, to eight, handing each datagram to the
  worker pool; no per-client state, no connection limit. See [how fast datagrams
  can be read](connections.md#how-fast-datagrams-can-be-read).
- **TCP, DoT and DoH**: a thread per connection, capped together by
  `server.max_connections` (512) and per client by
  [`max_connections_per_prefix`](connections.md#how-many-connections-one-client-may-hold)
  (half of it). TCP, DoT and HTTP/1.1 answer one query at a time per connection;
  **HTTP/2 multiplexes**. Connections are reused, so the cap bounds concurrent
  clients, not queries per second.

A connection's memory is its thread's: about 25 KB for TCP and 95 KB for DoT
held open after a query, most of the DoT figure OpenSSL's session. The thread's
scratch arena is mapped at its first query and unmapped when the connection
closes; of a DoT connection, about 90 KB stays in glibc's heaps after the close, reused
by the next burst rather than added to.
`--check` and startup warn when `max_connections` at 128 KB each is more than a
quarter of the memory elodin may use:

```
server.max_connections is 4096: with every connection open that is about 512.0 MiB, more than a quarter of the 1.0 GiB this process may use
```

Lower `max_connections`, or give elodin more memory (`MemoryMax=`). elodin turns
transparent huge pages off for itself at startup (`PR_SET_THP_DISABLE`): the
heaps glibc gives concurrent threads would otherwise each cost 2 MB resident once
touched, and a burst of connections would leave tens of MB behind.

HTTP/2 costs more CPU per query than HTTP/1.1 on cache hits, and wins when queries
are slow: a browser's concurrent requests overlap instead of queueing.

TLS handshakes are the expensive part of the encrypted transports, orders of
magnitude more CPU than answering on an open connection. ECDSA P-256 costs about
half what RSA-2048 does; `mise run certs` generates ECDSA, and production should
use it too.

Opening a connection is charged to the prefix's [rate
limit](rate-limiting.md#rate-limiting), per /24 and /64 only, and a refusal is
cheap rather than free. **If you expose DoT or DoH to the internet, rate-limit new
connections per source in front of the resolver**: see [a connection rate limit in
front](public-resolver.md#a-connection-rate-limit-in-front). The handshake-flood
figures are on [the same page](public-resolver.md#handshake-floods).

## Refused and failed connections

| counter | cause | what the client sees |
|---|---|---|
| `conn_refused=` | past `max_connections` or the client's share; the `warn` line says which | DoT/DoH: refused during the handshake. TCP: the kernel already completed it, so a reset on first use |
| `conn_rate_limited=` | the prefix opened connections faster than `rate_limit.responses_per_second` allows | closed on accept, before TLS |
| `conn_failed=` | the OS gave no thread (`RLIMIT_NPROC`, cgroup `pids.max`, memory); raising `max_connections` makes it worse | the same as `conn_refused=` |
| `accept_backoff=` | no file descriptor for the accept (`RLIMIT_NOFILE`) | nothing yet: the peer stays queued |

`conn_refused=` is kept apart from `refused=`: this is a client elodin would serve
and has no room for. A connection accepted as shutdown begins is closed and
counted under none of these.

A failing accept is retried at once three times in a row, with no wait and no
count. Past that the listener waits between attempts: up to 50 ms for errors on
individual connections, and up to a second on a descriptor shortage, where it
stops accepting; each wait is one
`accept_backoff=`, so a rate near one a second per listener is a listener taking
nothing. The `warn` naming the listener and `RLIMIT_NOFILE` is logged only once
it has spent about a second not accepting, so a burst that clears by itself is
silent.

## Measuring and disk

`mise run bench` measures all of this; see [`bench/README.md`](../bench/README.md).
Committed runs are under `bench/results/`: read them as the shape of the thing,
and re-take them rather than quoting an old run against a change.

On disk, `log.queries` writes a line per query and wants rotation. Nothing else
is written in steady state; the blocklist cache is the size of the lists.
