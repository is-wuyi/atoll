package node

import "testing"

// parseRange 收紧：拒绝尾部带非数字垃圾的 Range（此前 Sscanf 会静默接受）。
func TestParseRangeRejectsGarbage(t *testing.T) {
	bad := []string{"bytes=5abc-10", "bytes=5-10zz", "bytes=-3x", "bytes=abc-def", "bytes=1.5-2"}
	for _, h := range bad {
		if _, _, ok := parseRange(h, 1000); ok {
			t.Errorf("畸形 Range %q 应被拒绝，却被接受", h)
		}
	}
	// 合法输入仍然正确解析。
	if s, e, ok := parseRange("bytes=5-10", 1000); !ok || s != 5 || e != 10 {
		t.Errorf("bytes=5-10 → %d-%d ok=%v，期望 5-10 true", s, e, ok)
	}
	if s, e, ok := parseRange("bytes=-100", 1000); !ok || s != 900 || e != 999 {
		t.Errorf("bytes=-100 → %d-%d ok=%v，期望 900-999 true", s, e, ok)
	}
}
