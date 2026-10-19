package cache

import "core:slice"
import "core:testing"
import "core:time"
import "elodin:dns"

// Issue #165: an entry carrying signatures is not kept, or served stale, past
// the moment the first of them stops verifying (RFC 4034 section 3.1.5).

// An RRSIG over `covered` at `name`, expiring at `expiration`.
@(private = "file")
rrsig_record :: proc(name: string, covered: dns.Type, expiration: u32, section_ttl: u32) -> dns.Record {
	data := make([]u8, 35, context.temp_allocator)
	data[0], data[1], data[2], data[3] = u8(u16(covered) >> 8), u8(u16(covered)), 8, 2
	dns.write_ttl_at(data, 4, 86400) // original TTL
	dns.write_ttl_at(data, 8, expiration)
	dns.write_ttl_at(data, 12, expiration - 30 * 86400) // inception
	copy(data[16:], []u8{0x12, 0x34, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xde, 0xad, 0xbe, 0xef})
	return {name = name, type = .RRSIG, class = .IN, ttl = section_ttl, data = dns.Rdata_Raw{data = data}}
}

@(private = "file")
stored :: proc(c: ^Cache, m: dns.Message, qtype: dns.Type) -> (e: ^Entry, ok: bool) {
	wire, _, _ := dns.encode_message(m, context.temp_allocator)
	msg, _ := dns.decode_message(wire, context.temp_allocator)
	kb: [KEY_MAX]u8
	key := make_key(kb[:], "example.com.", qtype, .IN, true)
	if !put(c, key, wire, msg) {
		return nil, false
	}
	return c.entries[key]
}

// A signed A answer with a one-day TTL whose RRSIG lapses at `expiration`.
@(private = "file")
signed_answer :: proc(expiration: u32) -> dns.Message {
	// Cloned: a slice literal lives in this frame and would not outlive it.
	m := dns.Message {
		id       = 0x1111,
		question = slice.clone([]dns.Question{{name = "example.com.", type = .A, class = .IN}}, context.temp_allocator),
		answer   = slice.clone(
			[]dns.Record {
				{name = "example.com.", type = .A, class = .IN, ttl = 86400, data = dns.Rdata_A{addr = {1, 2, 3, 4}}},
				rrsig_record("example.com.", .A, expiration, 86400),
			},
			context.temp_allocator,
		),
	}
	m.flags.qr = true
	m.flags.ra = true
	m.flags.ad = true
	return m
}

// The issue's reproduction: neither the entry's expiry nor its stale deadline
// falls past the signature's.
@(test)
test_a_signed_entry_does_not_outlive_its_rrsig :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, serve_stale = true})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	e, ok := stored(c, signed_answer(now + 60), .A)
	testing.expect(t, ok, "put should succeed")
	if !ok {
		return
	}
	sig_expiry := time.unix(i64(now) + 60, 0)
	testing.expectf(t, time.diff(sig_expiry, e.expires) <= 0, "entry expires %v after its RRSIG does", time.diff(sig_expiry, e.expires))
	testing.expectf(
		t,
		time.diff(sig_expiry, deadline(c, e)) <= 0,
		"with serve_stale the entry is kept %v after its RRSIG expires",
		time.diff(sig_expiry, deadline(c, e)),
	)
	free_all(context.temp_allocator)
}

// A signature with days left changes nothing: the TTL still decides, and the
// stale window still follows it up to the signature.
@(test)
test_a_signature_with_time_left_leaves_the_entry_alone :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 3600, serve_stale = true})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	e, ok := stored(c, signed_answer(now + 7 * 86400), .A)
	testing.expect(t, ok, "put should succeed")
	if !ok {
		return
	}
	held := time.diff(e.inserted, e.expires)
	testing.expectf(t, held == 3600 * time.Second, "held %v, want the hour max_ttl allows", held)
	stale := time.diff(e.expires, deadline(c, e))
	testing.expectf(t, stale == MAX_STALE, "stale window %v, want MAX_STALE", stale)
	free_all(context.temp_allocator)
}

// The stale window ends at the signature even when the fresh life does not
// reach it.
@(test)
test_the_stale_window_ends_at_the_rrsig :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 300, serve_stale = true})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	e, ok := stored(c, signed_answer(now + 3600), .A)
	testing.expect(t, ok, "put should succeed")
	if !ok {
		return
	}
	testing.expectf(t, time.diff(e.inserted, e.expires) == 300 * time.Second, "held %v, want 300 s", time.diff(e.inserted, e.expires))
	sig_expiry := time.unix(i64(now) + 3600, 0)
	testing.expectf(t, time.diff(sig_expiry, deadline(c, e)) <= 0, "stale until %v past the RRSIG", time.diff(sig_expiry, deadline(c, e)))
	free_all(context.temp_allocator)
}

// A message whose signature has already lapsed is not stored at all.
@(test)
test_a_lapsed_signature_is_not_cached :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, serve_stale = true})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	_, ok := stored(c, signed_answer(now - 1), .A)
	testing.expect(t, !ok, "an answer whose signature lapsed a second ago was cached")
	free_all(context.temp_allocator)
}

// `min_ttl` is a floor on what the records claim, not on what the signature
// allows: the entry still goes when the RRSIG does.
@(test)
test_min_ttl_does_not_hold_an_entry_past_its_rrsig :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, min_ttl = 3600, max_ttl = 86400})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	e, ok := stored(c, signed_answer(now + 60), .A)
	testing.expect(t, ok, "put should succeed")
	if !ok {
		return
	}
	sig_expiry := time.unix(i64(now) + 60, 0)
	testing.expectf(t, time.diff(sig_expiry, e.expires) <= 0, "min_ttl kept the entry %v past its RRSIG", time.diff(sig_expiry, e.expires))
	// Nor does it raise what a copy is told past the signature.
	wire, _, hit := get(c, e.key, context.temp_allocator)
	testing.expect(t, hit, "the entry was not served")
	msg, _ := dns.decode_message(wire, context.temp_allocator)
	for rec in msg.answer {
		testing.expectf(t, rec.ttl <= 60, "%v went out with TTL %d under min_ttl, its RRSIG has 60 s left", rec.type, rec.ttl)
	}
	free_all(context.temp_allocator)
}

/*
A signed denial: the NSEC in the authority section, and its RRSIG, lapse long
before the SOA's figure. The entry is the proof as much as the SOA is, so it
goes when the NSEC's signature does.
*/
@(test)
test_a_signed_denial_does_not_outlive_its_nsec_rrsig :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, negative_ttl = 3600, serve_stale = true})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	soa_rdata := []u8 {
		2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		4, 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 0, 0, 1, 0, 0, 0x0e, 0x10, 0, 0, 0x0e, 0x10, 0, 0, 0x0e, 0x10, 0, 0, 0x0e, 0x10,
	}
	m := dns.Message {
		id        = 0x2222,
		question  = []dns.Question{{name = "example.com.", type = .TXT, class = .IN}},
		authority = []dns.Record {
			{name = "example.com.", type = .SOA, class = .IN, ttl = 3600, data = dns.Rdata_Raw{data = soa_rdata}},
			rrsig_record("example.com.", .SOA, now + 7 * 86400, 3600),
			{name = "example.com.", type = .NSEC, class = .IN, ttl = 3600, data = dns.Rdata_Raw{data = []u8{0, 0, 6, 0x40, 0, 0, 0, 0x03}}},
			rrsig_record("example.com.", .NSEC, now + 30, 3600),
		},
	}
	m.flags.qr = true
	m.flags.ra = true
	e, ok := stored(c, m, .TXT)
	testing.expect(t, ok, "put should succeed")
	if !ok {
		return
	}
	sig_expiry := time.unix(i64(now) + 30, 0)
	testing.expectf(t, time.diff(sig_expiry, e.expires) <= 0, "the denial is kept %v past its NSEC's RRSIG", time.diff(sig_expiry, e.expires))
	testing.expectf(t, time.diff(sig_expiry, deadline(c, e)) <= 0, "and served stale %v past it", time.diff(sig_expiry, deadline(c, e)))
	free_all(context.temp_allocator)
}


// Every copy served from the entry is told no more than the signature has left,
// whatever TTL the upstream gave: nothing here validated it when the client
// set CD.
@(test)
test_a_served_copy_is_told_no_more_than_the_rrsig_allows :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	e, ok := stored(c, signed_answer(now + 60), .A)
	testing.expect(t, ok, "put should succeed")
	if !ok {
		return
	}
	wire, _, hit := get(c, e.key, context.temp_allocator)
	testing.expect(t, hit, "the entry was not served")
	msg, _ := dns.decode_message(wire, context.temp_allocator)
	testing.expect_value(t, len(msg.answer), 2)
	for rec in msg.answer {
		testing.expectf(t, rec.ttl <= 60, "%v went out with TTL %d, its RRSIG has 60 s left", rec.type, rec.ttl)
	}
	free_all(context.temp_allocator)
}

// A stale copy is told no more than the signature has left either, where the
// fixed `STALE_TTL` would run past it.
@(test)
test_a_stale_copy_is_told_no_more_than_the_rrsig_allows :: proc(t: ^testing.T) {
	c := make_cache(Options{max_entries = 8, max_ttl = 86400, serve_stale = true})
	defer destroy(c)
	now := u32(time.time_to_unix(time.now()))
	e, ok := stored(c, signed_answer(now + 10), .A)
	testing.expect(t, ok, "put should succeed")
	if !ok {
		return
	}
	// Expired, with the signature still ten seconds from lapsing.
	e.expires = time.time_add(time.now(), -time.Second)
	wire, hit, served := get(c, e.key, context.temp_allocator)
	testing.expect(t, served && hit.stale, "the expired entry was not served stale")
	msg, _ := dns.decode_message(wire, context.temp_allocator)
	for rec in msg.answer {
		testing.expectf(t, rec.ttl <= 10, "%v went out stale with TTL %d, its RRSIG has 10 s left", rec.type, rec.ttl)
	}
	free_all(context.temp_allocator)
}
