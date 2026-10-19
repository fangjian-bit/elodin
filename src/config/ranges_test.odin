package config

import "core:strings"
import "core:testing"

@(private = "file")
refused :: proc(t: ^testing.T, doc, key, rule: string, loc := #caller_location) {
	_, err := load_string(doc, context.temp_allocator)
	e, has := err.?
	if !testing.expectf(t, has, "%s was accepted from:\n%s", key, doc, loc = loc) {
		return
	}
	found := false
	for m in e.messages {
		if strings.contains(m, key) && strings.contains(m, rule) {
			found = true
		}
	}
	testing.expectf(t, found, "no refusal names %s and %q: %v", key, rule, e.messages, loc = loc)
}

@(private = "file")
accepted :: proc(t: ^testing.T, doc: string, loc := #caller_location) {
	_, err := load_string(doc, context.temp_allocator)
	testing.expectf(t, err == nil, "refused: %v, from:\n%s", err, doc, loc = loc)
}

/*
A listener on port 0 binds whichever port the kernel picks, which no client can
be told; one past 65535 used to bind the port it wraps to (#316). Either way the
server comes up somewhere nothing asked for, so both are refused - the metrics
endpoint's rule, and like it only for a listener that binds.
*/
@(test)
test_a_listener_port_outside_1_to_65535_is_refused :: proc(t: ^testing.T) {
	base :: "upstream:\n  servers: [1.1.1.1]\nlisteners:\n"
	for key in ([]string{"udp", "tcp"}) {
		path := strings.concatenate({"listeners.", key, ".port"}, context.temp_allocator)
		for port in ([]string{"0", "-1", "65536", "106837"}) {
			doc := strings.concatenate({base, "  ", key, ":\n    enabled: true\n    port: ", port, "\n"}, context.temp_allocator)
			refused(t, doc, path, "between 1 and 65535")
		}
		accepted(t, strings.concatenate({base, "  ", key, ":\n    enabled: true\n    port: 65535\n"}, context.temp_allocator))
		accepted(t, strings.concatenate({base, "  ", key, ":\n    enabled: false\n    port: 0\n"}, context.temp_allocator))
	}
	// DoT and DoH go through the same check; their certificates are checked
	// later, so the port is what is read here.
	refused(t, base + "  dot:\n    enabled: true\n    port: 0\n", "listeners.dot.port", "between 1 and 65535")
	refused(t, base + "  doh:\n    enabled: true\n    port: 0\n", "listeners.doh.port", "between 1 and 65535")
	free_all(context.temp_allocator)
}

/*
RFC 2181 section 8: a TTL is 0 to 2^31-1, and a receiver treats one with the top
bit set as zero. A rewrite TTL of -1 went out on the wire as 4294967295 (#316),
and every other TTL this file sets - the cache's and the block answers' - could
be set past 2^31-1 the same way. Each is refused, at both ends, by name.
*/
@(test)
test_a_ttl_outside_rfc_2181_range_is_refused :: proc(t: ^testing.T) {
	rw :: proc(ttl: string) -> string {
		return strings.concatenate(
			{"upstream:\n  servers: [1.1.1.1]\nrewrites:\n  - domain: nas.home\n    answer: 192.168.1.50\n    ttl: ", ttl, "\n"},
			context.temp_allocator,
		)
	}
	refused(t, rw("-1"), "rewrites[0].ttl", "0 to 2147483647")
	refused(t, rw("2147483648"), "rewrites[0].ttl", "0 to 2147483647")
	refused(t, rw("4294967295"), "rewrites[0].ttl", "0 to 2147483647")
	accepted(t, rw("2147483647"))
	accepted(t, rw("0"))
	// Written as a duration, as every other TTL key can be.
	accepted(t, rw("5m"))

	for key in ([]string{"min_ttl", "max_ttl", "negative_ttl", "prefetch_min_ttl"}) {
		doc := strings.concatenate({"upstream:\n  servers: [1.1.1.1]\ncache:\n  ", key, ": 2147483648\n"}, context.temp_allocator)
		refused(t, doc, strings.concatenate({"cache.", key}, context.temp_allocator), "0 to 2147483647")
	}
	refused(t, "upstream:\n  servers: [1.1.1.1]\nblocking:\n  block_ttl: 2147483648\n", "blocking.block_ttl", "0 to 2147483647")
	refused(t, "upstream:\n  servers: [1.1.1.1]\nblocking:\n  block_ttl: -1\n", "blocking.block_ttl", "0 to 2147483647")
	accepted(t, "upstream:\n  servers: [1.1.1.1]\ncache:\n  min_ttl: 2147483647\n  max_ttl: 2147483647\n")
	accepted(t, "upstream:\n  servers: [1.1.1.1]\nblocking:\n  block_ttl: 2147483647\n")
	free_all(context.temp_allocator)
}

/*
`client_timeout` is how long an idle client connection is held. RFC 7766 6.2.3
recommends an idle period "on the order of seconds" and warns that long ones
exhaust a server; zero there means closing at once. Here a non-positive one was
no timeout at all, and anything under a microsecond truncates to a zero timeval
that SO_RCVTIMEO also reads as forever (#316). Refused under a millisecond, the
same floor as `upstream.timeout`.
*/
@(test)
test_a_client_timeout_under_1ms_is_refused :: proc(t: ^testing.T) {
	doc :: proc(v: string) -> string {
		return strings.concatenate({"upstream:\n  servers: [1.1.1.1]\nserver:\n  client_timeout: ", v, "\n"}, context.temp_allocator)
	}
	for v in ([]string{"0s", "0", "0.5us", "999us", "0.5ms"}) {
		refused(t, doc(v), "server.client_timeout", "at least 1ms")
	}
	// A duration has no sign, so this one never parses.
	refused(t, doc("-1s"), "server.client_timeout", "expected a duration")
	accepted(t, doc("1ms"))
	accepted(t, doc("10s"))
	free_all(context.temp_allocator)
}
