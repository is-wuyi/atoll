package node

import (
	"bytes"
	"os"
	"testing"

	"atoll/pkg/types"
)

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

// storeObject 带期望校验和：匹配则落盘，不符则拒绝且不留对象。
func TestStoreObjectChecksumVerify(t *testing.T) {
	n, _ := newTestNode(t)
	data := []byte("checksum-verified-content")
	good := types.CRC32C(data)

	// 匹配：成功落盘。
	if _, got, err := n.storeObject(1, bytes.NewReader(data), good); err != nil || got != good {
		t.Fatalf("匹配校验和应成功: got=%08x err=%v", got, err)
	}
	// 不符：拒绝落盘，且旧对象/新对象都不应存在于该 id。
	if _, _, err := n.storeObject(2, bytes.NewReader(data), good^0xffff); err == nil {
		t.Fatal("校验和不符应拒绝落盘")
	}
	if _, err := os.Stat(n.objectPathForTest(2)); !os.IsNotExist(err) {
		t.Fatal("校验和不符时不应留下对象文件")
	}
}
