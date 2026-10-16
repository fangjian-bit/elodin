package config

import "core:fmt"
import "core:strings"
import "core:testing"

/*
A name the file does not give is the url up to its query, in both spellings of
an upstream and of a list: a query can carry a key, and the name is what the log
and the `upstream` label on /metrics show (#487).
*/
@(test)
test_a_default_name_holds_no_query :: proc(t: ^testing.T) {
	for src in ([]string {
		"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/dns-query?token=SECRET\"]\n",
		"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{url: \"https://dns.example/dns-query?token=SECRET#frag\"}]\n",
		"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/dns-query#SECRET\"]\n",
	}) {
		cfg, err := load_string(src, context.temp_allocator)
		if e, has := err.?; has {
			testing.expectf(t, false, "%q: %v", src, e.messages)
			continue
		}
		s := cfg.upstream.servers[0]
		testing.expect_value(t, s.name, "https://dns.example/dns-query")
		// The query is still what the upstream is asked with.
		testing.expect(t, strings.contains(s.path, "SECRET") == strings.contains(src, "?token"))
	}
	for list in ([]string{"https://lists.example/hosts?key=SECRET", "{url: \"https://lists.example/hosts?key=SECRET#x\"}"}) {
		cfg, err := load_string(
			fmt.tprintf("upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists:\n    - %s\n", list),
			context.temp_allocator,
		)
		if e, has := err.?; has {
			testing.expectf(t, false, "%s: %v", list, e.messages)
			continue
		}
		testing.expect_value(t, cfg.blocking.lists[0].name, "https://lists.example/hosts")
		testing.expect(t, strings.contains(cfg.blocking.lists[0].url, "key=SECRET"))
	}
	// A name the file gives is kept as written.
	cfg, err := load_string(
		"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"mine?x\", url: \"https://dns.example/q?token=SECRET\"}]\n",
		context.temp_allocator,
	)
	if e, has := err.?; has {
		testing.expectf(t, false, "%v", e.messages)
	} else {
		testing.expect_value(t, cfg.upstream.servers[0].name, "mine?x")
	}
	free_all(context.temp_allocator)
}

/*
Two different servers, or two lists, that would go by one default name are
refused: their counters would sum into one series, their log lines read as one,
and two lists would share one cache file. The same server listed twice, a name
the file gives to more than one server, and lists that differ in name are not.
*/
@(test)
test_a_default_name_names_one_thing :: proc(t: ^testing.T) {
	Case :: struct {
		src: string,
		ok:  bool,
	}
	cases := []Case {
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/q?a=1\", \"https://dns.example/q?a=2\"]\n", false},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/q?a=1\"]\n  zones:\n    - domains: [corp.example]\n      servers: [{url: \"https://dns.example/q?a=2\"}]\n", false},
		{"upstream:\n  servers: [\"tls://1.1.1.1#one.one.one.one\", \"tls://1.1.1.1#cloudflare-dns.com\"]\n", false},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: \"https://dns.example/q\", url: \"https://dns.example/r\"}, \"https://dns.example/q?a=1\"]\n", false},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [\"https://dns.example/q?a=1\"]\n  zones:\n    - domains: [corp.example]\n      servers: [\"https://dns.example/q?a=1#x\"]\n", true},
		{"upstream:\n  bootstrap: [1.1.1.1]\n  servers: [{name: a, url: \"https://dns.example/q?a=1\"}, {name: b, url: \"https://dns.example/q?a=2\"}]\n", true},
		{"upstream:\n  servers: [{name: cf, address: 1.1.1.1}, {name: cf, address: 1.0.0.1}]\n", true},
		{"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [\"https://l.example/h?k=1\"]\n  allowlists: [\"https://l.example/h?k=2\"]\n", false},
		{"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [{name: x, url: \"https://l.example/a\"}, {name: x, url: \"https://l.example/b\"}]\n", false},
		{"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [\"https://l.example/a_b\", \"https://l.example/a/b\"]\n", false},
		{"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [\"https://l.example/h?k=1\", {name: two, url: \"https://l.example/h?k=2\"}, {url: \"https://l.example/h?k=3\", enabled: false}]\n", true},
		{"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [\"https://l.example/h?k=1\"]\n  allowlists: [\"https://l.example/h?k=1\"]\n", true},
		{"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [\"https://l.example/h?k=1\", \"https://l.example/h?k=1#x\"]\n", true},
		{"upstream:\n  servers: [1.1.1.1]\nblocking:\n  lists: [{url: \"https://l.example/h?k=1\", file: /a}, {url: \"https://l.example/h?k=2\", file: /b}]\n", true},
	}
	for c in cases {
		_, err := load_string(c.src, context.temp_allocator)
		e, has := err.?
		testing.expectf(t, has != c.ok, "%q: refused %v (%v)", c.src, has, e.messages if has else nil)
		if has {
			for m in e.messages {
				testing.expectf(t, !strings.contains(m, "a=") && !strings.contains(m, "k="), "the refusal shows the query: %s", m)
			}
		}
	}
	free_all(context.temp_allocator)
}
