package meta

import "atoll/pkg/types"

// Old readers bind reports to the content generation; a failed read never deletes a physical copy.
func (s *Store) MarkLegacyReplicaSuspect(id, nodeID, generation uint64, size int64, checksum uint32) (bool, error) {
	changed := false
	err := s.write(func(w *txw) error {
		in, err := getInodeTx(w.tx, id)
		if err != nil {
			return err
		}
		if in.Type != types.TypeFile || in.Chunked || in.Staging ||
			in.Generation != generation || in.Size != size || in.Checksum != checksum ||
			(checksum == 0 && in.ObjID == 0) {
			return nil
		}
		d, ok := describeInodeObject(in, types.ObjIDFor(in))
		if !ok {
			return nil
		}
		changed, err = markSuspectTx(w, d, nodeID)
		return err
	})
	return changed, err
}
