package node

import (
	"fmt"
	"io"
	"os"

	"atoll/pkg/types"
)

// An identical immutable retry can re-confirm existing bytes without allocating another full object.
// This path still validates both the stored object and the complete incoming body.
// fence, when non-nil, re-checks the planned-write generation immediately before
// the replay is accepted, so a retry admitted under a superseded layout cannot
// re-confirm the object under the old generation.
func (n *Node) verifyStoredReplay(id uint64, body io.Reader, size int64, checksum uint32, fence publishFence) (bool, error) {
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
	if err := n.checkObjectFence(id); err != nil {
		return false, err
	}
	// 世代闸在重放被接受之前执行：世代已推进时，既有字节不再被旧世代确认。
	if fence != nil {
		if err := fence(); err != nil {
			return false, err
		}
	}
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
