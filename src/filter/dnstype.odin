package filter

import "core:mem"
import "core:reflect"
import "core:slice"
import "elodin:dns"

/*
`$dnstype`: a rule narrowed to some query types (#406).

urlfilter reads `$dnstype=A|~AAAA` into a permitted and a restricted list, and a
rule matches a type the restricted list does not name and, when the permitted
one names any, one it does (`matchDNSType`). So a rule is either "one of P \ R"
or, permitting none, "anything but R": one `Type_Filter`. Several rules for one
name match what any of them does, and that union is one of the two shapes again
(`type_union`), so a name holds one filter however many rules name it.

A filter lists at most MAX_RULE_TYPES types, which bounds what adding a rule
costs: a union only ever shrinks an exclusion, and grows a permitted list to the
bound, past which the rule is skipped - as any rule this engine cannot honour is
skipped rather than widened.
*/
MAX_RULE_TYPES :: 64

Type_Filter :: struct {
	// Sorted, without repeats.
	types:   []u16,
	// The filter matches every type but `types`.
	negated: bool,
}

// What a rule with no `$dnstype` matches. The zero filter matches nothing.
ANY_TYPE :: Type_Filter{nil, true}

type_matches :: proc(f: Type_Filter, qtype: dns.Type) -> bool {
	_, found := slice.binary_search(f.types, u16(qtype))
	return found != f.negated
}

/*
`$dnstype`'s value, as urlfilter's `parseDNSTypes` reads it, with its types in
`buf`; false for one it refuses, which skips the rule, and for one that names
every type it permits as excluded too, which matches nothing. A type is a
mnemonic in any case, or RFC 3597 section 5's `TYPEnnn`, which urlfilter refuses.
*/
@(private)
parse_dnstype :: proc(value: string, buf: []u16) -> (f: Type_Filter, ok: bool) {
	permit, exclude: [MAX_RULE_TYPES + 1]u16
	np, ne := 0, 0
	rest := value
	for {
		bar := len(rest)
		for i in 0 ..< len(rest) {
			if rest[i] == '|' {
				bar = i
				break
			}
		}
		item := rest[:bar]
		negated := len(item) > 0 && item[0] == '~'
		if negated {
			item = item[1:]
		}
		t := parse_type_name(item) or_return
		if negated {
			if ne == len(exclude) {
				return
			}
			exclude[ne] = t
			ne += 1
		} else {
			if np == len(permit) {
				return
			}
			permit[np] = t
			np += 1
		}
		if bar == len(rest) {
			break
		}
		rest = rest[bar + 1:]
	}
	slice.sort(permit[:np])
	slice.sort(exclude[:ne])
	ps := slice.unique(permit[:np])
	es := slice.unique(exclude[:ne])
	if len(ps) + len(es) > MAX_RULE_TYPES || len(buf) < MAX_RULE_TYPES {
		return
	}
	if len(ps) == 0 {
		return {buf[:copy(buf, es)], true}, true
	}
	n := sorted_combine(ps, es, true, false, false, buf)
	return {buf[:n], false}, n > 0
}

@(private)
parse_type_name :: proc(s: string) -> (t: u16, ok: bool) {
	buf: [16]u8
	if len(s) == 0 || len(s) > len(buf) {
		return
	}
	for i in 0 ..< len(s) {
		c := s[i]
		switch c {
		case 'a' ..= 'z':
			c -= 32
		case '-':
			// IANA's `NSAP-PTR` is the enum's `NSAP_PTR`.
			c = '_'
		case '_':
			return
		}
		buf[i] = c
	}
	name := string(buf[:len(s)])
	if len(name) > 4 && name[:4] == "TYPE" {
		n := 0
		for c in transmute([]u8)name[4:] {
			if c < '0' || c > '9' || n > 0xffff {
				return
			}
			n = n * 10 + int(c - '0')
		}
		return u16(n), n > 0 && n <= 0xffff
	}
	// `None` is spelt so that no upper-cased name finds it; it is type 0, which
	// urlfilter refuses too.
	v, found := reflect.enum_from_name(dns.Type, name)
	return u16(v), found && v != .None
}

/*
What matches either filter, in `allocator` unless it is `a` again; false when
that lists more than MAX_RULE_TYPES types.

Either list: their union. Anything but either list: anything but what both
name. One of P, or anything but R: anything but what R names and P does not.
*/
@(private)
type_union :: proc(a, b: Type_Filter, allocator: mem.Allocator) -> (out: Type_Filter, ok: bool) {
	buf: [2 * MAX_RULE_TYPES]u16
	n: int
	switch {
	case !a.negated && !b.negated:
		n = sorted_combine(a.types, b.types, true, true, true, buf[:])
	case a.negated && b.negated:
		n = sorted_combine(a.types, b.types, false, false, true, buf[:])
	case a.negated:
		n = sorted_combine(a.types, b.types, true, false, false, buf[:])
	case:
		n = sorted_combine(b.types, a.types, true, false, false, buf[:])
	}
	if n > MAX_RULE_TYPES {
		return
	}
	out.negated = a.negated || b.negated
	if out.negated == a.negated && slice.equal(buf[:n], a.types) {
		return a, true
	}
	out.types = slice.clone(buf[:n], allocator) if n > 0 else nil
	return out, true
}

// Walk two sorted lists together, keeping what is only in `x`, only in `y`, or
// in both, as asked; returns how many went into `out`.
@(private)
sorted_combine :: proc(x, y: []u16, x_only, y_only, both: bool, out: []u16) -> (n: int) {
	i, j := 0, 0
	for i < len(x) || j < len(y) {
		v: u16
		keep: bool
		switch {
		case j == len(y) || (i < len(x) && x[i] < y[j]):
			v, keep = x[i], x_only
			i += 1
		case i == len(x) || y[j] < x[i]:
			v, keep = y[j], y_only
			j += 1
		case:
			v, keep = x[i], both
			i += 1
			j += 1
		}
		if keep {
			out[n] = v
			n += 1
		}
	}
	return
}
