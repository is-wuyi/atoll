//go:build !darwin && !linux

package peertransport

// On platforms without a portable O_NOFOLLOW the Lstat + fd.Stat + SameFile
// check in openRuntimeIdentity still rejects symlink swaps; this build only
// loses the at-open-time hardening, never the identity validation itself.
const identityOpenFlags = 0
