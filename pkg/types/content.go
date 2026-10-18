package types

import "errors"

// ValidatePlainContent checks the currently executable manifest geometry, not future EC or COW layouts.
func ValidatePlainContent(in Inode) error {
	if in.Content == nil {
		return errors.New("content version required")
	}
	v := in.Content
	if in.Type != TypeFile || in.Staging || !in.Chunked || in.ObjID != 0 || in.Generation == 0 || v.ID < StagingInodeBase || v.ID > MaxStagingInode || in.Size < 0 || in.Size != v.LogicalSize || len(v.Extents) != len(in.Chunks) || len(v.Extents) > MaxChunksPerFile {
		return errors.New("invalid plain content version")
	}
	var offset int64
	for i, extent := range v.Extents {
		o, ch := extent.Object, in.Chunks[i]
		if extent.Offset != offset || extent.ObjectOffset != 0 || extent.Length <= 0 || extent.Length > ChunkSize || extent.Length > in.Size-offset || (i < len(v.Extents)-1 && extent.Length != ChunkSize) {
			return errors.New("invalid plain extent range")
		}
		if o.ID != ChunkID(v.ID, i) || o.Version != 1 || o.LogicalSize != extent.Length || o.StoredSize != o.LogicalSize || o.Encoding != PlainEncoding || !o.ChecksumKnown {
			return errors.New("invalid plain extent object")
		}
		if ch.ID != o.ID || ch.Index != i || ch.Size != o.StoredSize || ch.Checksum != o.Checksum || !ch.ChecksumKnown || len(ch.Replicas) == 0 {
			return errors.New("content and compatibility chunk table differ")
		}
		seen := make(map[uint64]bool, len(ch.Replicas))
		for _, id := range ch.Replicas {
			if id == 0 || seen[id] {
				return errors.New("content replicas must be distinct nodes")
			}
			seen[id] = true
		}
		for _, list := range [][]uint64{ch.Done, ch.Suspect} {
			members := make(map[uint64]bool, len(list))
			for _, id := range list {
				if !seen[id] || members[id] {
					return errors.New("content receipt is not a distinct assigned node")
				}
				members[id] = true
			}
		}
		offset += extent.Length
	}
	if offset != in.Size {
		return errors.New("content extents do not cover file")
	}
	return nil
}
