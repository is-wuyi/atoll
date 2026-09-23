//go:build darwin

package mount

import "syscall"

// xattrNotFound 是"扩展属性不存在"的错误码。
// macOS 上是 ENOATTR(93)——Finder 据此判定"该文件没有这个 xattr"，正常继续；
// 若误用 ENODATA(96) 会被当成真 I/O 错误，Finder 中止拷贝弹 -43。
const xattrNotFound = syscall.Errno(93) // ENOATTR on Darwin
