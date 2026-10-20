package server

import "core:encoding/base32"
import "core:strings"
import "core:testing"
import "elodin:dns"
import "elodin:dnssec"

@(private = "file")
APEX :: "corp.example.com."

@(private = "file")
BASE32HEX := [32]byte {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
}

// A window-0 type bitmap (RFC 4034 section 4.1.2) holding `types`.
@(private = "file")
type_bitmap :: proc(types: ..dns.Type) -> []u8 {
	bits := make([]u8, 32, context.temp_allocator)
	top := 0
	for t in types {
		bits[int(t) / 8] |= 0x80 >> (uint(t) % 8)
		top = max(top, int(t) / 8 + 1)
	}
	out := make([dynamic]u8, context.temp_allocator)
	append(&out, 0, u8(top))
	append(&out, ..bits[:top])
	return out[:]
}

// An NSEC at `owner` whose next name is `next`.
@(private = "file")
nsec_at :: proc(owner, next: string, types: ..dns.Type) -> dns.Record {
	rdata := make([dynamic]u8, context.temp_allocator)
	for label in strings.split(strings.trim_suffix(next, "."), ".", context.temp_allocator) {
		append(&rdata, u8(len(label)))
		append(&rdata, label)
	}
	append(&rdata, 0)
	append(&rdata, ..type_bitmap(..types))
	return dns.Record{name = owner, type = .NSEC, class = .IN, ttl = 300, data = dns.Rdata_Raw{data = rdata[:]}}
}

/*
An NSEC3 in `example.com.` for the span from `from` to `to`, no salt. `from` nil
is the hash of `APEX` at `iterations`, which makes the record the one matching it.
*/
@(private = "file")
nsec3_at :: proc(from, to: []u8, flags: u8, iterations: u16, types: ..dns.Type) -> dns.Record {
	owner := from
	if owner == nil {
		owner = make([]u8, 20, context.temp_allocator)
		dnssec.nsec3_hash(APEX, nil, iterations, owner)
	}
	rdata := make([dynamic]u8, context.temp_allocator)
	append(&rdata, 1, flags, u8(iterations >> 8), u8(iterations), 0, 20)
	append(&rdata, ..to)
	append(&rdata, ..type_bitmap(..types))
	label := base32.encode(owner, BASE32HEX, context.temp_allocator)
	return dns.Record {
		name = strings.concatenate({label, ".example.com."}, context.temp_allocator),
		type = .NSEC3,
		class = .IN,
		ttl = 300,
		data = dns.Rdata_Raw{data = rdata[:]},
	}
}

@(private = "file")
nodata :: proc(authority: ..dns.Record) -> []u8 {
	question := make([]dns.Question, 1, context.temp_allocator)
	question[0] = dns.Question{name = APEX, type = .DS, class = .IN}
	msg := dns.Message{question = question, authority = authority}
	msg.flags.qr = true
	msg.flags.rd = true
	msg.flags.ra = true
	wire, _, err := dns.encode_message(msg, context.temp_allocator)
	if err != .None {
		return nil
	}
	return wire
}

/*
Issue #244: a NODATA for an apex `DS` is the insecure delegation's proof only
where the denial records do not show the parent holding the name itself.

RFC 4035 section 5.2 gives the proof as an NSEC at the name with NS set and DS
clear, RFC 5155 section 8.9 the NSEC3 one, opt-out included, and RFC 6840
section 4.4 rules out the child's own apex record standing for it. A record at
the name with NS clear - an A record for a portal - or records showing the name
as an empty non-terminal are a name the parent holds, and the route answers.
What the records cannot settle - none at all, which is an unsigned parent, a
record past the iteration ceiling, an opt-out span - keeps the NODATA as the
proof: only a positive showing turns it away.
*/
@(test)
test_an_apex_ds_nodata_is_the_proof_unless_the_denial_shows_no_delegation :: proc(t: ^testing.T) {
	zero := make([]u8, 20, context.temp_allocator)
	ones := make([]u8, 20, context.temp_allocator)
	for &b in ones {
		b = 0xff
	}
	Case :: struct {
		what:   string,
		reply:  []u8,
		proved: bool,
	}
	cases := []Case {
		{"no denial records", nodata(), true},
		{"an NSEC with NS", nodata(nsec_at(APEX, "example.", .NS, .RRSIG, .NSEC)), true},
		{"an NSEC without NS", nodata(nsec_at(APEX, "example.", .A, .RRSIG, .NSEC)), false},
		{"the child's apex NSEC", nodata(nsec_at(APEX, "example.", .NS, .SOA, .RRSIG, .NSEC, .DNSKEY)), false},
		{"an empty non-terminal", nodata(nsec_at("example.com.", "vpn.corp.example.com.", .NS, .SOA, .RRSIG, .NSEC)), false},
		{"an NSEC3 with NS", nodata(nsec3_at(nil, zero, 0, 0, .NS)), true},
		{"an NSEC3 without NS", nodata(nsec3_at(nil, zero, 0, 0, .A, .RRSIG)), false},
		{"an NSEC3 past the ceiling", nodata(nsec3_at(nil, zero, 0, 150, .A, .RRSIG)), true},
		{"an opt-out span", nodata(nsec3_at(zero, ones, 1, 0, .NS, .SOA)), true},
		{"a span that is not opt-out", nodata(nsec3_at(zero, ones, 0, 0, .NS, .SOA)), false},
	}

	// The premise: each reply is a NODATA whose authority the decoder hands over.
	for c in cases {
		m, err := dns.decode_message(c.reply, context.temp_allocator)
		if !testing.expectf(t, err == .None, "%s: %v", c.what, err) {
			return
		}
		testing.expectf(t, len(m.answer) == 0 && dns.Rcode(m.flags.rcode) == .No_Error, "%s is not a NODATA", c.what)
	}
	nsec := nodata(nsec_at(APEX, "example.", .A, .RRSIG, .NSEC))
	m, _ := dns.decode_message(nsec, context.temp_allocator)
	types := m.authority[0].data.(dns.Rdata_Raw).data[9:]
	testing.expect(t, !dnssec.bitmap_has(types, .NS) && dnssec.bitmap_has(types, .A), "the held name's NSEC has the NS bit")

	for c in cases {
		spent := 0
		proved, settled := parent_answers_apex_ds(c.reply, APEX, true, &spent, 100, context.temp_allocator)
		testing.expectf(t, proved == c.proved, "%s: proved %v, want %v", c.what, proved, c.proved)
		// The proof is settled; what is not the proof is no fact to store against.
		testing.expectf(t, settled == c.proved, "%s: settled %v", c.what, settled)
	}
	free_all(context.temp_allocator)
}
