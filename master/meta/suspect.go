package meta

import "atoll/pkg/types"

// MarkLegacyReplicaSuspect 只撤销同一内容版本的完成标记，不删除数据。
// 小文件覆盖复用对象 ID，校验旧快照得到的不匹配不能使新版本失去副本。
func (s *Store) MarkLegacyReplicaSuspect(id, nodeID, generation uint64, size int64, checksum uint32) (bool, error) {
	changed := false
	err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile || in.Chunked || in.Staging {
			return nil
		}
		if in.Generation != generation || in.Size != size || in.Checksum != checksum || checksum == 0 {
			return nil
		}
		if !types.ContainsUint64(in.Replicas, nodeID) || !types.ContainsUint64(in.DoneReplicas, nodeID) {
			return nil
		}
		filtered := make([]uint64, 0, len(in.DoneReplicas)-1)
		for _, d := range in.DoneReplicas {
			if d != nodeID {
				filtered = append(filtered, d)
			}
		}
		in.DoneReplicas = filtered
		if err := w.putInode(&in); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}
