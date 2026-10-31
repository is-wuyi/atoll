//go:build darwin || linux

package peertransport

import "syscall"

// identityOpenFlags refuses to follow a symlink and refuses to block on a FIFO
// or device node. A symlink swap between Lstat and open is rejected at open
// time, and a FIFO opens immediately (instead of blocking forever) so the
// caller can reject it after stat.
const identityOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
