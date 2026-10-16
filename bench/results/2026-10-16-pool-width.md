# elodin benchmark

Measured on unknown CPU (4 logical cores, 8 GB RAM, Linux 7.0.0-38-generic), elodin dev-cca0601.

Mock upstream held at 20ms. DNSSEC off. Each run 10s measured after 2s of warmup, median of 3, 3s idle between runs.

Cores were averaging 0 MHz when the run finished. This is a 15 W laptop part that cannot hold its boost clock through the whole matrix, so treat the absolute figures as the shape of the thing rather than a specification.

## Pool width and the running limit

Server pinned to CPUs 0-1, generator to 2-3, 128 clients over UDP, `max_pending` 1024 throughout.

| workers / running_workers | cache misses | miss p99 | cache hits | hit p99 |
|---|---|---|---|---|
| 16 / 16 (no limit) | 493 qps | 394.3 ms | 435,300 qps | 1.3 ms |
| 128 / 128 (no limit) | 3,794 qps | 65.9 ms | 207,994 qps | 6.0 ms |
| 128 / derived (4) | 4,066 qps | 64.9 ms | 359,980 qps | 2.5 ms |

