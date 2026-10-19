package config

import "core:strings"
import "core:testing"
import "core:time"

/*
An upstream `timeout` under a millisecond is refused, at the top level and on a
route (#499).

It is what every exchange with one server is given, and a query's budget is two
of them, so zero is not "wait as long as it takes": the query has run out before
it starts, a dial gets a one-millisecond connect window, and every query answers
SERVFAIL. A millisecond is the smallest wait the sockets and `poll` underneath
can express, so anything shorter reads as zero there too.
*/
@(test)
test_an_upstream_timeout_under_a_millisecond_is_refused :: proc(t: ^testing.T) {
	refused :: proc(t: ^testing.T, doc, key: string) {
		_, err := load_string(doc, context.temp_allocator)
		e, has := err.?
		if testing.expectf(t, has, "%s was accepted from:%s", key, doc) {
			testing.expectf(t, strings.contains(e.messages[0], key), "the refusal does not name %s: %v", key, e.messages)
		}
	}
	refused(t, "upstream:\n  timeout: 0s\n  servers: [1.1.1.1]\n", "upstream.timeout")
	refused(t, "upstream:\n  timeout: 0.5ms\n  servers: [1.1.1.1]\n", "upstream.timeout")
	refused(
		t,
		"upstream:\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      timeout: 0\n      servers: [192.168.1.1]\n",
		"upstream.zones[0].timeout",
	)

	// The smallest figure that is a wait, at both levels.
	cfg, err := load_string(
		"upstream:\n  timeout: 1ms\n  servers: [1.1.1.1]\n  zones:\n    - domains: [home.arpa]\n      timeout: 1ms\n      servers: [192.168.1.1]\n",
		context.temp_allocator,
	)
	if e, has := err.?; has {
		testing.expectf(t, false, "a 1ms timeout was refused: %v", e.messages)
	} else {
		testing.expect_value(t, cfg.upstream.timeout, time.Millisecond)
		testing.expect_value(t, cfg.upstream.zones[0].upstream.timeout, time.Millisecond)
	}
	free_all(context.temp_allocator)
}
