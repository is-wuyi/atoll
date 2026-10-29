package node

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"atoll/pkg/types"
)

// legacyPlannedDescriptor 复用 recoveryPlan 的形态构造一个"非 recovery"的
// 计划分块 descriptor：世代为 0 时协议必须是 integrity-v1（见 replicationPlan
// 的协议↔世代耦合校验），否则节点会以 "unsupported replication protocol" 拒绝。
func legacyPlannedDescriptor(objID uint64, data []byte) types.ReplicationPlan {
	plan := recoveryPlan(objID, data, 0)
	plan.Protocol = types.IntegrityProtocol
	plan.Object.WriteEpoch = 0
	plan.WriteProgress = nil
	return plan
}

// ingressLegs 构造 write-transfer 计划；ingress 为 true 时含 0→self 的客户端
// 上传腿，为 false 时 self 只作为 relay 目标（7→self），不含任何 0→self 腿。
func ingressLegs(self uint64, ingress bool) *types.WriteTransferPlan {
	legs := []types.WriteTransferLeg{
		{FromNodeID: 0, ToNodeID: 7, Path: "direct", BPS: 1024},
		{FromNodeID: 7, ToNodeID: self, Path: "direct", BPS: 1024},
	}
	targets := []uint64{7}
	if ingress {
		legs = append(legs, types.WriteTransferLeg{FromNodeID: 0, ToNodeID: self, Path: "direct", BPS: 1024})
		targets = append(targets, self)
	}
	return &types.WriteTransferPlan{
		UploadTargets: targets,
		Legs:          legs,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
}

func TestRecoveryRegressionLegacyEpochZeroPutIgnoresMasterReceipt(t *testing.T) {
	data := []byte("legacy chunk payload, receipt refused")
	objID := recoveryChunkID(3)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	m.setPlan(objID, legacyPlannedDescriptor(objID, data))
	// master 明确拒收回执（4xx：世代过期/副本改派/内容变化）。若修复后仍走
	// 同步回执，这里必然 409；503（不可达）同理，只是多 3 次重试。
	m.setReceiptStatus(http.StatusConflict)

	resp := putWithEpoch(t, ts.URL, objID, data, 0, false)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("legacy (epoch 0) chunk PUT must keep the pre-recovery contract: 201 without requiring a master receipt; got %d body=%q (bytes published=%v)",
			resp.StatusCode, string(body), chunkObjectExists(t, n, objID))
	}
	if !chunkObjectExists(t, n, objID) {
		t.Fatal("legacy chunk bytes must be published")
	}
}

func TestRecoveryRegressionResumeRequiresUploadIngressLeg(t *testing.T) {
	data := []byte("resume ingress probe")
	objID := recoveryChunkID(6)
	n, ts := newTestNode(t)
	m := attachEpochMaster(t, n)
	plan := recoveryPlan(objID, data, 1)

	// 本地已有字节：resume 的语义是"零长度重确认已落盘对象"。
	crc := types.CRC32C(data)
	if _, _, err := n.storeVerifiedObject(objID, bytes.NewReader(data), &crc, int64(len(data))); err != nil {
		t.Fatal(err)
	}

	// 阶段一：节点 2 不是客户端上传 ingress（仅 relay 目标）。
	plan.WriteTransfer = ingressLegs(2, false)
	m.setPlan(objID, plan)

	if resp := putWithEpoch(t, ts.URL, objID, data, 1, false); resp.StatusCode != http.StatusConflict {
		t.Fatalf("payload PUT on a non-ingress node must be refused by the transfer-leg gate; got %d", resp.StatusCode)
	}
	if resp := putWithEpoch(t, ts.URL, objID, nil, 1, true); resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("resume on a non-ingress node must be refused by the same gate; got %d body=%q", resp.StatusCode, string(body))
	}
	if verified, _, _, _ := m.snapshot(); len(verified) != 0 {
		t.Fatalf("a refused resume must not emit any receipt: %v", verified)
	}

	// 阶段二（正向对照）：配上 0→self 的 ingress 腿后，resume 恢复 200 且恰好一条回执。
	plan.WriteTransfer = ingressLegs(2, true)
	m.setPlan(objID, plan)

	resp := putWithEpoch(t, ts.URL, objID, nil, 1, true)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("resume on a proper client-upload ingress node must succeed; got %d body=%q", resp.StatusCode, string(body))
	}
	if verified, _, _, _ := m.snapshot(); len(verified) != 1 {
		t.Fatalf("resume on an ingress node must produce exactly one verified receipt; got %d", len(verified))
	}
}

func TestRecoveryRegressionReplicateRejectsResumeHeader(t *testing.T) {
	data := []byte("relay payload carrying a resume header")
	objID := recoveryChunkID(8)

	t.Run("control: normal replicate leg still publishes", func(t *testing.T) {
		n, ts := newTestNode(t)
		m := attachEpochMaster(t, n)
		m.setPlan(objID, recoveryPlan(objID, data, 1))

		req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/replicate/%d", ts.URL, objID), bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(data)))
		req.Header.Set(types.WriteEpochHeader, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("normal replicate leg must keep working; got %d", resp.StatusCode)
		}
		if !chunkObjectExists(t, n, objID) {
			t.Fatal("normal replicate leg must publish the bytes")
		}
	})

	t.Run("resume header on /replicate must be refused", func(t *testing.T) {
		n, ts := newTestNode(t)
		m := attachEpochMaster(t, n)
		m.setPlan(objID, recoveryPlan(objID, data, 1))

		req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/replicate/%d", ts.URL, objID), bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(data)))
		req.Header.Set(types.WriteEpochHeader, "1")
		req.Header.Set(types.WriteResumeHeader, "true")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		code := resp.StatusCode
		resp.Body.Close()

		// 契约：拒绝且绝不发布。建议实现返回 400（与 handlePut 的世代头校验
		// 一致）；409 亦可接受——两者都表明这是请求形态错误而非节点故障，
		// 调用方不应重试。
		if code != http.StatusBadRequest && code != http.StatusConflict {
			t.Fatalf("PUT /replicate carrying X-Atoll-Write-Resume must be refused (want 400 or 409); got %d body=%q", code, string(body))
		}
		if chunkObjectExists(t, n, objID) {
			t.Fatal("a resume-flagged replicate must not publish bytes")
		}
	})
}
