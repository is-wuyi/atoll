//go:build !darwin

package mount

import "syscall"

// xattrNotFound 是"扩展属性不存在"的错误码。
// Linux 上 ENODATA==ENOATTR==61，语义为"该文件没有这个 xattr"。
const xattrNotFound = syscall.ENODATA
