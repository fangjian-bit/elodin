package config

import "core:strings"

/*
The name a server or list goes by when the file gives it none: its url up to the
query. A query can carry a key or a per-user profile, and the name is what the
log shows and what every `upstream` label on /metrics carries; RFC 9110 17.9 has
a target logged and displayed where third parties see it. The fragment is never
sent at all (RFC 3986 3.5). The authority ends before either (RFC 3986 3.2), and
a url with userinfo is refused at load, so what is left is scheme, host, port and
path.
*/
url_name :: proc(url: string) -> string {
	if i := strings.index_any(url, "?#"); i >= 0 {
		return url[:i]
	}
	return url
}

// The file a downloaded list is cached under in `blocking.cache_dir`.
list_cache_name :: proc(name: string, allocator := context.temp_allocator) -> string {
	b := strings.builder_make(allocator)
	for i in 0 ..< len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
			strings.write_byte(&b, c)
		case:
			strings.write_byte(&b, '_')
		}
	}
	strings.write_string(&b, ".list")
	return strings.to_string(b)
}

/*
A default name is one the operator never chose, so two different servers that
get the same one are refused: they would sum into one series on /metrics and
read as one in the log, with nothing in the file to tell them apart. One server
listed twice, in the default group and a route say, is one server. A name the
file gives to several servers is the operator's choice to count them as one.
*/
@(private)
check_default_upstream_names :: proc(l: ^Loader, cfg: ^Config) {
	seen := make(map[string]Upstream_Spec, context.temp_allocator)
	visit :: proc(l: ^Loader, seen: ^map[string]Upstream_Spec, specs: []Upstream_Spec) {
		for s in specs {
			prev, found := seen[s.name]
			if !found {
				seen[s.name] = s
				continue
			}
			same := prev.kind == s.kind && prev.address == s.address && prev.port == s.port && prev.hostname == s.hostname && prev.path == s.path && prev.verify == s.verify
			if !same && (is_default_name(prev) || is_default_name(s)) {
				errorf(l, "upstream: two different servers both go by %q; give one a 'name:' (in the map form of a server)", s.name)
			}
		}
	}
	visit(l, &seen, cfg.upstream.servers)
	for route in cfg.upstream.zones {
		visit(l, &seen, route.upstream.servers)
	}

	is_default_name :: proc(s: Upstream_Spec) -> bool {
		return s.name == describe_upstream(s, context.temp_allocator)
	}
}

/*
A downloaded list is cached under its name, so two lists with different urls
that come to one cache file - one name, or two names that differ only where the
file name cannot hold them - would read each other's copy whenever a download
fails. Refused at load, by the name that would be shared. A disabled list is
never downloaded, nor is one with a `file:`, which is read in place of its url.
Two entries for one url are one list, the fragment aside, which is never sent.
*/
@(private)
check_list_cache_names :: proc(l: ^Loader, cfg: ^Config) {
	seen := make(map[string]Block_List, context.temp_allocator)
	for lists in ([][]Block_List{cfg.blocking.lists, cfg.blocking.allow_lists}) {
		for bl in lists {
			if bl.url == "" || bl.file != "" || !bl.enabled {
				continue
			}
			file := list_cache_name(bl.name)
			prev, found := seen[file]
			if !found {
				seen[file] = bl
			} else if strings.truncate_to_byte(prev.url, '#') != strings.truncate_to_byte(bl.url, '#') {
				errorf(l, "blocking: the lists named %q and %q would share the cache file %s; give one a different 'name:'", prev.name, bl.name, file)
			}
		}
	}
}
