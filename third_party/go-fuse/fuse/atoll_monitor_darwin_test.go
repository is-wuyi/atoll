//go:build darwin

package fuse

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"testing"
	"unsafe"
)

func TestMonitorNotificationsNeverReply(t *testing.T) {
	for _, nodeID := range []uint64{FUSE_ROOT_ID, 42, pollHackInode} {
		for _, code := range []uint32{1, 2} {
			server := &protocolServer{opts: &MountOptions{Logger: log.New(io.Discard, "", 0)}}
			input := MonitorIn{InHeader: InHeader{Opcode: _OP_MONITOR, NodeId: nodeID, Unique: 123}, Flags: code}
			input.Length = uint32(unsafe.Sizeof(input))
			var raw bytes.Buffer
			if err := binary.Write(&raw, binary.LittleEndian, input); err != nil {
				t.Fatal(err)
			}
			output := bytes.Repeat([]byte{0xa5}, int(sizeOfOutHeader))
			req := &request{inputBuf: raw.Bytes(), outHeaderBuf: output, cancel: make(chan struct{})}
			server.handleRequest(operationHandlers[_OP_MONITOR], req)
			if !req.suppressReply {
				t.Errorf("MONITOR code=%d inode=%d generated status %v instead of suppressing its reply", code, nodeID, req.status)
			}
			if !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, int(sizeOfOutHeader))) {
				t.Errorf("MONITOR code=%d inode=%d serialized a reply", code, nodeID)
			}
			if len(server.reqInflight) != 0 {
				t.Error("notification remained in flight")
			}
		}
	}
}
