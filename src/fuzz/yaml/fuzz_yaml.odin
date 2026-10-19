package fuzz_yaml

import "elodin:fuzz/harness"
import "elodin:yaml"

// yaml.parse takes a string, so the buffer is cast rather than validated —
// invalid UTF-8 is exactly the kind of input the parser needs to survive, since
// it reads the configuration file at load. Downloaded blocklists do not come
// through here: they go to `filter.parse_list`, which `fuzz_list` covers.
@(export, link_name = "LLVMFuzzerTestOneInput")
fuzz_one :: proc "c" (data: [^]u8, size: uint) -> i32 {
	f: harness.Fuzz_Arena
	context = harness.setup(&f)
	defer harness.teardown(&f)

	root, _ := yaml.parse(string(data[:size]))
	read_scalars(root)
	return 0
}

/*
Every scalar through every reader the loader uses on one, which is where a
figure written in the file becomes a number. A duration is never negative: the
parser takes no sign, and parts too large to hold saturate rather than wrap
round, so one that comes back negative is a wrapped sum - a figure that could
equally have wrapped into a small one and passed a caller's bounds.
*/
read_scalars :: proc(n: ^yaml.Node) {
	if n == nil {
		return
	}
	_, _ = yaml.as_bool(n)
	_, _ = yaml.as_int(n)
	_, _ = yaml.as_bytes(n)
	if d, ok := yaml.as_duration(n); ok {
		assert(d >= 0, "a duration read negative")
	}
	for child in n.seq {
		read_scalars(child)
	}
	for _, child in n.fields {
		read_scalars(child)
	}
}
