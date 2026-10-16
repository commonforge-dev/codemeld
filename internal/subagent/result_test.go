package subagent

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBoundReply_UnderAndAtCapIsUntouched(t *testing.T) {
	for _, size := range []int{0, 1, maxReplyBytes - 1, maxReplyBytes} {
		in := strings.Repeat("a", size)
		got, truncated := boundReply(in)
		if truncated {
			t.Fatalf("boundReply(%d bytes) reported truncation", size)
		}
		if got != in {
			t.Fatalf("boundReply(%d bytes) altered the reply", size)
		}
	}
}

func TestBoundReply_OverCapTruncatesAtCap(t *testing.T) {
	in := strings.Repeat("a", maxReplyBytes+1)
	got, truncated := boundReply(in)
	if !truncated {
		t.Fatal("boundReply did not report truncation past the cap")
	}
	if len(got) != maxReplyBytes {
		t.Fatalf("bounded reply is %d bytes, want %d", len(got), maxReplyBytes)
	}
}

func TestBoundReply_DoesNotSplitARune(t *testing.T) {
	// Two bytes of padding leave a 3-byte rune straddling the cap.
	in := "xy" + strings.Repeat("€", maxReplyBytes)
	got, truncated := boundReply(in)
	if !truncated {
		t.Fatal("boundReply did not report truncation past the cap")
	}
	if !utf8.ValidString(got) {
		t.Fatal("bounded reply split a multi-byte rune")
	}
	if len(got) >= maxReplyBytes || len(got) < maxReplyBytes-utf8.UTFMax {
		t.Fatalf("bounded reply is %d bytes, want just under %d", len(got), maxReplyBytes)
	}
}
