package upstream

import "core:testing"
import "elodin:logx"

/*
A kind of failure is reported again once its window has passed.

It used to be reported once per upstream per kind for the life of the process, so
an upstream that had timed out on its first day and began refusing handshakes on
its fortieth was `debug` from then on: the counters moved and the log said
nothing about why. The clock is the case's own, so the window can be crossed
without waiting for it.
*/
@(test)
test_a_failure_kind_is_reported_again_after_its_window :: proc(t: ^testing.T) {
	u: Upstream
	start := i64(1_000_000)

	loud, held := note_failure_kind_at(&u, .Timeout, start)
	testing.expect(t, loud, "the first timeout was not reported")
	testing.expect_value(t, held, 0)

	loud, _ = note_failure_kind_at(&u, .Timeout, start + 1)
	testing.expect(t, !loud, "a second timeout in the same window was reported")

	// Another kind has a window of its own: one noisy kind must not hide the
	// first appearance of a different one.
	loud, _ = note_failure_kind_at(&u, .TLS_Failed, start + 2)
	testing.expect(t, loud, "a different kind was silenced by the first")

	loud, held = note_failure_kind_at(&u, .Timeout, start + i64(logx.GATE_WINDOW))
	testing.expect(t, loud, "a timeout was not reported again after its window")
	testing.expect_value(t, held, 1)
}
