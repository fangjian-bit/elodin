package fuzz_dnssec

import "elodin:dns"
import "elodin:dnssec"
import "elodin:fuzz/harness"

/*
The DNSSEC RDATA parsers, and the DER that `verify_signature` builds out of an
upstream's DNSKEY and RRSIG bytes before `d2i_PUBKEY` and the verifier see it.

The first byte is the algorithm and the next two say where the rest splits into a
public key and a signature, so every key and signature encoder - RSA's exponent
length, ECDSA's r and s, the Edwards keys - is reached with bytes of any length.
What is asked of it is only that it accepts or refuses without reading or
writing out of bounds; the verdict is not the point.

The whole input is also read as a reply, and its authority section handed to
`denial_shows_no_cut`, which reads an upstream's NSEC and NSEC3 records without
verifying them first (issue #244).
*/
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	if size < 3 {
		return 0
	}
	rest := data[3:size]
	_, _ = dnssec.parse_rrsig(rest)
	_, _ = dnssec.parse_dnskey(rest)
	_, _ = dnssec.parse_ds(rest)
	if n, err := dnssec.parse_nsec(rest); err == .None {
		_ = dnssec.bitmap_has(n.types, .A)
		_ = dnssec.bitmap_has(n.types, .DS)
	}
	if n, err := dnssec.parse_nsec3(rest); err == .None {
		_ = dnssec.bitmap_has(n.types, .NSEC3)
	}

	if m, err := dns.decode_message(data[:size]); err == .None && len(m.question) == 1 {
		_ = dnssec.denial_shows_no_cut(m.authority, m.question[0].name, 100, context.allocator)
	}

	split := (int(data[1]) << 8 | int(data[2])) % (len(rest) + 1)
	_ = dnssec.verify_signature(data[0], rest[:split], rest[split:], rest)
	return 0
}
