package node

import (
	"fmt"
	"io"
	"os"

	"atoll/pkg/types"
)

// An identical immutable retry can re-confirm existing bytes without allocating another full object.
// This path still validates both the stored object and the complete incoming body.
func (n *Node) verifyStoredReplay(id uint64, body io.Reader, size int64, checksum uint32) (bool, error) {
	path := n.objectPath(id)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() != size {
		return false, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return false, fmt.Errorf("stored replay object changed")
	}
	h := types.NewCRC32C()
	stored, err := io.Copy(h, io.LimitReader(f, size+1))
	if err != nil {
		return false, err
	}
	if stored != size || h.Sum32() != checksum {
		return false, nil
	}
	h.Reset()
	received, err := io.Copy(h, io.LimitReader(body, size+1))
	if err != nil {
		return false, err
	}
	if received != size || h.Sum32() != checksum {
		return false, fmt.Errorf("%w: retry payload differs from immutable object", errIntegrityMismatch)
	}
	lock := n.objectLock(id)
	lock.Lock()
	defer lock.Unlock()
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) || current.Size() != size {
		return false, fmt.Errorf("stored replay object changed during verification")
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	if err := syncObjectDirectories(path); err != nil {
		return false, err
	}
	return true, nil
}
