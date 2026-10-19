package types

import (
	"encoding/json"
	"testing"
)

func TestAeadContentManifestValidation(t *testing.T) {
	id := StagingInodeBase
	logical := int64(AeadRecordPlaintext + 10)
	stored, sizeErr := AeadStoredSize(logical)
	if sizeErr != nil {
		t.Fatal(sizeErr)
	}
	object := ContentObject{ID: ChunkID(id, 0), Version: 1, LogicalSize: logical, StoredSize: stored, Encoding: AeadRecordEncoding, ChecksumKnown: true}
	valid := Inode{ID: id, Type: TypeFile, Chunked: true, Size: logical, Generation: 1, Content: &ContentVersion{ID: id, LogicalSize: logical, Extents: []ContentExtent{{Length: logical, Object: object}}},
		Chunks: []ChunkInfo{{ID: object.ID, Index: 0, Size: stored, LogicalSize: logical, Encoding: AeadRecordEncoding, ChecksumKnown: true, Replicas: []uint64{1}, Done: []uint64{1}}}}
	if err := ValidateContentManifest(valid); err != nil {
		t.Fatal(err)
	}
	// 同一 manifest 对 plain 校验必须拒绝（编码分派不能互相放行）。
	if err := ValidatePlainContent(valid); err == nil {
		t.Fatal("aead manifest passed the plain-only validator")
	}
	mutations := map[string]func(*Inode){
		"stored-size":     func(in *Inode) { in.Chunks[0].Size++; in.Content.Extents[0].Object.StoredSize++ },
		"logical-size":    func(in *Inode) { in.Chunks[0].LogicalSize-- },
		"encoding-drop":   func(in *Inode) { in.Chunks[0].Encoding = "" },
		"encoding-plain":  func(in *Inode) { in.Content.Extents[0].Object.Encoding = PlainEncoding },
		"unknown-member":  func(in *Inode) { in.Chunks[0].Done = []uint64{2} },
		"extent-length":   func(in *Inode) { in.Content.Extents[0].Length-- },
		"chunk-mismatch":  func(in *Inode) { in.Chunks[0].ChecksumKnown = false },
		"overrun":         func(in *Inode) { in.Content.Extents[0].Object.LogicalSize = ChunkSize + 1; in.Content.Extents[0].Length = ChunkSize + 1; in.Size = ChunkSize + 1; in.Content.LogicalSize = ChunkSize + 1; in.Chunks[0].LogicalSize = ChunkSize + 1 },
		"plain-disagrees": func(in *Inode) { in.Content.Extents[0].Object.Encoding = PlainEncoding },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(valid)
			var in Inode
			if err := json.Unmarshal(raw, &in); err != nil {
				t.Fatal(err)
			}
			mutate(&in)
			if err := ValidateContentManifest(in); err == nil {
				t.Fatal("invalid aead manifest accepted")
			}
		})
	}
}

func TestPlainManifestStillValidatesUnderDispatcher(t *testing.T) {
	id := StagingInodeBase
	object := ContentObject{ID: ChunkID(id, 0), Version: 1, LogicalSize: 4, StoredSize: 4, Encoding: PlainEncoding, ChecksumKnown: true}
	valid := Inode{ID: id, Type: TypeFile, Chunked: true, Size: 4, Generation: 1, Content: &ContentVersion{ID: id, LogicalSize: 4, Extents: []ContentExtent{{Length: 4, Object: object}}},
		Chunks: []ChunkInfo{{ID: object.ID, Index: 0, Size: 4, ChecksumKnown: true, Replicas: []uint64{1}, Done: []uint64{1}}}}
	if err := ValidateContentManifest(valid); err != nil {
		t.Fatal(err)
	}
	// 编码分派后旧数据的坏 manifest 依然被拒绝。
	broken := valid
	broken.Content.Extents[0].Object.StoredSize = 5
	broken.Chunks[0].Size = 5
	if err := ValidateContentManifest(broken); err == nil {
		t.Fatal("plain geometry violation accepted")
	}
	// 旧 chunk 表不填 LogicalSize/Encoding 时 ChunkLogicalSize 回落到 Size。
	legacy := ChunkInfo{ID: object.ID, Index: 0, Size: 4, ChecksumKnown: true, Replicas: []uint64{1}, Done: []uint64{1}}
	if ChunkLogicalSize(legacy) != 4 || ChunkEncoding(legacy) != PlainEncoding {
		t.Fatal("legacy chunk helpers disagree")
	}
	// aead 块显式两个字段时按新值读取。
	aeadLogical := int64(AeadRecordPlaintext + 10)
	aeadStored, err := AeadStoredSize(aeadLogical)
	if err != nil {
		t.Fatal(err)
	}
	if ChunkLogicalSize(ChunkInfo{Size: aeadStored, LogicalSize: aeadLogical, Encoding: AeadRecordEncoding}) != aeadLogical {
		t.Fatal("aead chunk helper ignores logical size")
	}
	if ChunkEncoding(ChunkInfo{Encoding: AeadRecordEncoding}) != AeadRecordEncoding {
		t.Fatal("aead chunk helper drops encoding")
	}
}
