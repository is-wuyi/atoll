//go:build !unix

package edgeidentity

import "strings"

// 非 unix 无 O_NOFOLLOW/O_NONBLOCK：symlink 竞态防护退化为句柄 Stat 检查
// （symlink 指向 regular 且权限合规时会被接受），README 有说明。
const openKeyFlags = 0

func isSymlinkOpenErr(err error) bool { return false }

func linkUnsupported(err error) bool {
	return strings.Contains(err.Error(), "not supported")
}
