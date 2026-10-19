package types

import (
	"testing"

	"atoll/pkg/contentcrypto"
)

// TestAeadGeometryMatchesContentcrypto 校验 types 侧的纯几何函数与真实
// SealRecord 线格式逐字节对齐：记录边界、存储长度与封装开销必须一致。
func TestAeadGeometryMatchesContentcrypto(t *testing.T) {
	if AeadRecordPlaintext != contentcrypto.MaxRecordPlaintext {
		t.Fatalf("record plaintext %d != contentcrypto %d", AeadRecordPlaintext, contentcrypto.MaxRecordPlaintext)
	}
	for _, logical := range []int64{1, 100, AeadRecordPlaintext, AeadRecordPlaintext + 1, 2 * AeadRecordPlaintext, 3*AeadRecordPlaintext - 5} {
		stored, err := AeadStoredSize(logical)
		if err != nil {
			t.Fatalf("logical=%d: %v", logical, err)
		}
		dek, _ := contentcrypto.NewDEK()
		var wire []byte
		count, _ := AeadRecordCount(logical)
		for i := 0; i < count; i++ {
			n := AeadRecordPlaintext
			if i == count-1 {
				n = int(logical - int64(i)*AeadRecordPlaintext)
			}
			rec, err := contentcrypto.SealRecord(dek, 42, 7, uint64(i), make([]byte, n))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if len(rec) != n+AeadRecordOverhead {
				t.Fatalf("logical=%d record len %d != %d", logical, len(rec), n+AeadRecordOverhead)
			}
			// 边界函数与真实记录逐条对齐
			start, length, plain, err := AeadRecordExtent(i, logical)
			if err != nil {
				t.Fatalf("extent: %v", err)
			}
			if int64(len(rec)) != length || start+length > int64(len(wire))+int64(length) || plain != int64(n) {
				t.Fatalf("extent mismatch: start=%d length=%d plain=%d record=%d", start, length, plain, len(rec))
			}
			wire = append(wire, rec...)
		}
		if int64(len(wire)) != stored {
			t.Fatalf("logical=%d wire %d != stored %d", logical, len(wire), stored)
		}
		// 逻辑偏移 → 记录定位与解密往返
		for _, off := range []int64{0, 1, logical / 2, logical - 1} {
			idx, storedOff, err := AeadRecordIndex(off)
			if err != nil {
				t.Fatalf("index: %v", err)
			}
			_, _, _, err = AeadRecordExtent(idx, logical)
			if err != nil {
				t.Fatalf("extent for index: %v", err)
			}
			_, length, _, _ := AeadRecordExtent(idx, logical)
			plain, oerr := contentcrypto.OpenRecord(dek, 42, 7, uint64(idx), wire[storedOff:storedOff+length])
			wantPlain := int64(AeadRecordPlaintext)
			if idx == count-1 {
				wantPlain = logical - int64(idx)*AeadRecordPlaintext
			}
			if oerr != nil || int64(len(plain)) != wantPlain {
				t.Fatalf("open record %d: %v len=%d want=%d", idx, oerr, len(plain), wantPlain)
			}
		}
	}
	if s, _ := AeadStoredSize(0); s != 0 {
		t.Fatal("empty stored size != 0")
	}
	if _, err := AeadRecordCount(-1); err == nil {
		t.Fatal("negative accepted")
	}
	if err := ValidateChunkGeometry(AeadRecordEncoding, AeadRecordPlaintext, AeadRecordPlaintext+AeadRecordOverhead); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChunkGeometry(AeadRecordEncoding, 1, 1+AeadRecordOverhead*2); err == nil {
		t.Fatal("wrong aead stored size accepted")
	}
	if err := ValidateChunkGeometry(PlainEncoding, 5, 5); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChunkGeometry(PlainEncoding, 5, 6); err == nil {
		t.Fatal("plain size mismatch accepted")
	}
	if err := ValidateChunkGeometry("ec-v1", 1, 1); err == nil {
		t.Fatal("unknown encoding accepted")
	}
}
