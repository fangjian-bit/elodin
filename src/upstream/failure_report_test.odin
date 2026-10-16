package upstream

import "core:testing"
import "elodin:logx"

/*
A kind of failure is reported again once its window has passed.

Once per upstream per kind for the life of the process would leave an upstream
that timed out on its first day and began refusing handshakes on its fortieth
at `debug` from then on: the counters move and the log says nothing about why. The clock is the case's own, so the window can be crossed
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

/*
A handshake failure is one event and says so once.

The transport writes the line with the reason and `record_failure` then asks
about the same event. Asking the same gate twice counted it twice, and at a
window's edge handed the warning to the generic line, so the reason went to
debug. The handshake has a gate of its own per kind, and the generic line for
that kind waits for it.
*/
@(test)
test_a_handshake_failure_is_said_once_with_its_reason :: proc(t: ^testing.T) {
	u: Upstream
	now := i64(1_000_000)

	loud, _ := logx.gate_pass(&u.handshake[.TLS_Failed], now)
	testing.expect(t, loud, "the handshake line was not due")

	holdback: u64
	loud, holdback = note_failure_kind_at(&u, .TLS_Failed, now + 1)
	testing.expect(t, !loud, "the generic line repeated a handshake failure that has its reason")
	testing.expect_value(t, holdback, 0)

	// The kind's own count is untouched, so it does not drift from the events.
	testing.expect_value(t, u.reported[.TLS_Failed].held, 0)

	// A failure of another kind is not a handshake failure.
	loud, _ = note_failure_kind_at(&u, .Timeout, now + 1)
	testing.expect(t, loud, "a timeout was held back by a handshake window")

	// And once the handshake window has passed the generic line speaks again,
	// for a TLS_Failed that did not come through the handshake path.
	loud, _ = note_failure_kind_at(&u, .TLS_Failed, now + i64(logx.GATE_WINDOW))
	testing.expect(t, loud, "the generic line stayed silent after the handshake window")
}


/*
Each kind a handshake can fail as waits only for its own handshake line.

`handshake_failure` maps a handshake to `TLS_Failed`, `Verify_Failed` or
`Timeout`. With one gate for all three, a handshake that timed out would silence
the first `TLS_Failed` - and, with a timeout a minute, every one after it - and a
`Verify_Failed` handshake would be said twice: once with its reason, once more by
the kind's own line, which nothing held back.
*/
@(test)
test_a_handshake_holds_back_only_its_own_kind :: proc(t: ^testing.T) {
	kinds := [?]Error{.TLS_Failed, .Verify_Failed, .Timeout}
	now := i64(1_000_000)
	for kind in kinds {
		u: Upstream
		loud, _ := logx.gate_pass(&u.handshake[kind], now)
		testing.expectf(t, loud, "the %v handshake line was not due", kind)

		loud, _ = note_failure_kind_at(&u, kind, now + 1)
		testing.expectf(t, !loud, "a %v handshake was said twice", kind)

		for other in kinds {
			if other == kind {
				continue
			}
			loud, _ = note_failure_kind_at(&u, other, now + 1)
			testing.expectf(t, loud, "a %v handshake silenced the first %v", kind, other)
		}
	}
}
