package types

import "errors"

// ValidateContentManifest 按 inode 内容清单的编码分派几何校验。plain 保持
// ValidatePlainContent 的全部既有断言（旧数据永久兼容）；aead-record-v1 是新写
// 编码，要求块表显式携带逻辑长度与编码且与 manifest 对象一致。
// 空清单（无 Extents 的空文件）只验公共形状。
func ValidateContentManifest(in Inode) error {
	v := in.Content
	if in.Type != TypeFile || in.Staging || !in.Chunked || in.ObjID != 0 || in.Generation == 0 || v == nil ||
		v.ID < StagingInodeBase || v.ID > MaxStagingInode || in.Size < 0 || in.Size != v.LogicalSize ||
		len(v.Extents) != len(in.Chunks) || len(v.Extents) > MaxChunksPerFile {
		return errors.New("invalid content manifest")
	}
	if len(v.Extents) == 0 {
		if in.Size != 0 {
			return errors.New("non-empty size without extents")
		}
		return nil
	}
	var offset int64
	for i, extent := range v.Extents {
		o, ch := extent.Object, in.Chunks[i]
		if extent.Offset != offset || extent.ObjectOffset != 0 || extent.Length <= 0 || extent.Length > ChunkSize || extent.Length > in.Size-offset || (i < len(v.Extents)-1 && extent.Length != ChunkSize) {
			return errors.New("invalid extent range")
		}
		if o.ID != ChunkID(v.ID, i) || o.Version != 1 || o.LogicalSize != extent.Length || !o.ChecksumKnown {
			return errors.New("invalid extent object")
		}
		if err := ValidateChunkGeometry(o.Encoding, o.LogicalSize, o.StoredSize); err != nil {
			return err
		}
		if ch.ID != o.ID || ch.Index != i || ch.Size != o.StoredSize || ch.Checksum != o.Checksum || !ch.ChecksumKnown || len(ch.Replicas) == 0 {
			return errors.New("content and compatibility chunk table differ")
		}
		if ChunkEncoding(ch) != o.Encoding {
			return errors.New("chunk table encoding differs from manifest")
		}
		if ch.LogicalSize != 0 && ch.LogicalSize != o.LogicalSize {
			return errors.New("chunk table logical size disagrees with manifest")
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
