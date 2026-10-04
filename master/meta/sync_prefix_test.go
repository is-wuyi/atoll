package meta

import (
	"bytes"
	"testing"
)

// EncodeFrameSyncBlob：把 FramesSince 读回的帧直接打成 wal-sync-<seq> 单帧段 blob，
// 供 master 的前缀补齐钩子使用；必须能被 DecodeWALSegment 原样还原。
func TestEncodeFrameSyncBlobRoundTrip(t *testing.T) {
	want := Frame{Seq: 7, Muts: []mutation{
		{Bucket: bcInodes, Key: []byte("inode-7"), Value: []byte(`{"id":7}`)},
		{Bucket: bcChildren, Key: []byte("child-key"), Del: true},
		{Bucket: bcMeta, Key: []byte("counter"), Value: []byte{0, 0, 0, 0, 0, 0, 0, 9}},
	}}
	blob := EncodeFrameSyncBlob(want)
	// 单帧段 = 8B seq + 4B len + frame body。
	if len(blob) != 12+len(blob)-12 {
		t.Fatalf("blob 长度异常: %d", len(blob))
	}
	got, err := DecodeWALSegment(blob)
	if err != nil {
		t.Fatalf("DecodeWALSegment: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("应还原 1 帧，got %d", len(got))
	}
	f := got[0]
	if f.Seq != want.Seq || len(f.Muts) != len(want.Muts) {
		t.Fatalf("帧不符: seq=%d muts=%d", f.Seq, len(f.Muts))
	}
	for i, m := range want.Muts {
		g := f.Muts[i]
		if g.Bucket != m.Bucket || g.Del != m.Del || !bytes.Equal(g.Key, m.Key) || !bytes.Equal(g.Value, m.Value) {
			t.Fatalf("mut %d 不符: %+v vs %+v", i, g, m)
		}
	}
}
