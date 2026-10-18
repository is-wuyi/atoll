//go:build unix

package edgeidentity

import (
	"errors"
	"strings"
	"syscall"
)

// openKeyFlags：O_NOFOLLOW 关闭“路径在 Lstat→open 之间被换成 symlink”的竞态
// （symlink 直接 open 失败）；O_NONBLOCK 防 FIFO/设备类文件在 open 时阻塞。
const openKeyFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// isSymlinkOpenErr 判定 open 失败是否因目标为 symlink（O_NOFOLLOW 下为 ELOOP）。
func isSymlinkOpenErr(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

// linkUnsupported 判定文件系统是否不支持 hard link（如部分网络挂载）。
// 这些 errno 之外的文案兜底：部分 FUSE/SMB 实现返回非标准错误。
func linkUnsupported(err error) bool {
	for _, target := range []error{
		syscall.ENOSYS, syscall.EPERM, syscall.EINVAL, syscall.EXDEV, syscall.EOPNOTSUPP,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return strings.Contains(err.Error(), "not supported")
}
