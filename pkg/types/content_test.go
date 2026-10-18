package types

import (
	"encoding/json"
	"testing"
)

func TestPlainContentManifestValidation(t *testing.T) {
	id := StagingInodeBase
	object := ContentObject{ID: ChunkID(id, 0), Version: 1, LogicalSize: 4, StoredSize: 4, Encoding: PlainEncoding, ChecksumKnown: true}
	valid := Inode{ID: id, Type: TypeFile, Chunked: true, Size: 4, Generation: 1, Content: &ContentVersion{ID: id, LogicalSize: 4, Extents: []ContentExtent{{Length: 4, Object: object}}}, Chunks: []ChunkInfo{{ID: object.ID, Index: 0, Size: 4, ChecksumKnown: true, Replicas: []uint64{1}, Done: []uint64{1}}}}
	if err := ValidatePlainContent(valid); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Inode){
		"offset":         func(in *Inode) { in.Content.Extents[0].Offset++ },
		"object-offset":  func(in *Inode) { in.Content.Extents[0].ObjectOffset++ },
		"length":         func(in *Inode) { in.Content.Extents[0].Length-- },
		"encoding":       func(in *Inode) { in.Content.Extents[0].Object.Encoding = "aead" },
		"physical-size":  func(in *Inode) { in.Content.Extents[0].Object.StoredSize++ },
		"object":         func(in *Inode) { in.Content.Extents[0].Object.ID++ },
		"missing":        func(in *Inode) { in.Content.Extents = nil },
		"generation":     func(in *Inode) { in.Generation = 0 },
		"crc":            func(in *Inode) { in.Chunks[0].ChecksumKnown = false },
		"unknown-member": func(in *Inode) { in.Chunks[0].Done = []uint64{2} },
		"duplicate-node": func(in *Inode) { in.Chunks[0].Replicas = []uint64{1, 1} },
		"overrun":        func(in *Inode) { in.Content.Extents[0].Length = ChunkSize + 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(valid)
			var in Inode
			if err := json.Unmarshal(raw, &in); err != nil {
				t.Fatal(err)
			}
			mutate(&in)
			if err := ValidatePlainContent(in); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	empty := Inode{ID: id, Type: TypeFile, Chunked: true, Generation: 1, Content: &ContentVersion{ID: id}}
	if err := ValidatePlainContent(empty); err != nil {
		t.Fatal(err)
	}
}
