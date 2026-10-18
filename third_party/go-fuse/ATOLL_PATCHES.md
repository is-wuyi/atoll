# Atoll local go-fuse patch

Source: `github.com/hanwen/go-fuse/v2 v2.11.0`, copied byte-for-byte from the Go module archive after `go mod verify`. Upstream LICENSE and source files are retained. The root `go.mod` uses a local `replace` directive so the fix is reproducible and does not depend on a modified module cache.

## Local changes

- `fuse/opcode_darwin.go`: declare `SuppressReply: true` for macFUSE's `MONITOR` notification. The protocol dispatcher overwrites the per-request flag with this handler-level field. Without it, ordinary monitor notifications emit replies and notifications for `.go-fuse-epoll-hack` emit `ERANGE`; these unsolicited replies can collide with subsequent request IDs.
- `fuse/atoll_monitor_darwin_test.go`: verify both monitor flag variants for the root, an ordinary inode and the poll-hack inode. No notification may serialize a reply.

No dependency versions or non-Darwin production behavior are changed. Remove the local replacement only after an upstream version with equivalent notification handling passes both the protocol regression and Atoll's kernel startup tests.

```bash
NO_PROXY='*' no_proxy='*' go -C third_party/go-fuse test -race ./fuse -run TestMonitorNotificationsNeverReply -count=1
NO_PROXY='*' no_proxy='*' go test -race -tags fuse ./mount -run TestKernelMountFirstMutation -count=1
```

The protocol regression does not require a mount. Atoll's `-tags fuse` tests require a working FUSE environment; skipped kernel tests do not count as acceptance.
