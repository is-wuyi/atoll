package node

// node/security_hardening_helpers_test.go —— security_hardening_test.go 的辅助函数
// （与既有测试同包共享 json/编解码约定，单独文件避免干扰既有 fixture）。

import (
	"bytes"
	"encoding/json"

	"atoll/pkg/types"
)

func jsonUnmarshalForTest(data []byte, v any) error { return json.Unmarshal(data, v) }

func jsonMarshalForTest(v any) ([]byte, error) { return json.Marshal(v) }

func checksumForTest(b []byte) uint32 { return types.CRC32C(b) }

func planForTest(data []byte, crc uint32, srcURL string) types.ReplicationPlan {
	return types.ReplicationPlan{
		Protocol: types.IntegrityProtocol,
		Object: types.ObjectIntegrity{
			ObjectID: 300, InodeID: 300, Size: int64(len(data)),
			Checksum: crc, ChecksumKnown: true, Replicas: []uint64{1, 2},
		},
		Sources: []types.NodeInfo{{ID: 1, Addr: trimHTTPForTest(srcURL)}},
	}
}

func trimHTTPForTest(u string) string {
	const prefix = "http://"
	if len(u) > len(prefix) && u[:len(prefix)] == prefix {
		return u[len(prefix):]
	}
	return u
}

// jsonEqualForTest 供将来断言使用（保留以对齐既有 bytesEqual 习惯）。
func jsonEqualForTest(a, b []byte) bool { return bytes.Equal(a, b) }
