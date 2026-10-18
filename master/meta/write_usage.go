package meta

import (
	"encoding/json"
	"fmt"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

func validNodeUsage(u types.NodeUsage) bool {
	return u.Epoch != "" && len(u.Epoch) <= 128 && u.Sequence > 0 && u.UsedBytes >= 0
}

func applyNodeUsage(node *types.NodeInfo, usage types.NodeUsage) error {
	if !validNodeUsage(usage) {
		return ErrWritePlanConflict
	}
	if node.UsageFloorBytes < 0 || node.UsedBytes < 0 {
		return ErrWritePlanConflict
	}
	if node.Usage != nil && node.Usage.Epoch == usage.Epoch {
		if node.Usage.Sequence > usage.Sequence {
			return nil
		}
		if node.Usage.Sequence == usage.Sequence && node.Usage.UsedBytes != usage.UsedBytes {
			return ErrWritePlanConflict
		}
	} else if node.Usage != nil || usage.UsedBytes < node.UsedBytes {
		// Epochs have no ordering. A switch cannot release previously accounted bytes.
		node.UsageFloorBytes = max(node.UsageFloorBytes, max(node.UsedBytes, usage.UsedBytes))
	}
	node.UsedBytes = usage.UsedBytes
	node.Usage = &usage
	return nil
}

func writeUsageKey(objectID, nodeID uint64) []byte {
	return []byte(fmt.Sprintf("receipt/%d/%d", objectID, nodeID))
}

func recordWriteUsage(w *txw, current types.ObjectIntegrity, nodeID uint64, usage *types.NodeUsage) error {
	if usage == nil || current.ObjectID < types.StagingInodeBase<<8 {
		return nil
	}
	if current.ObjectID >= types.ObjectIDBase {
		return recordProtectionUsage(w, current, nodeID, usage)
	}
	origin, _ := types.ParseChunkID(current.ObjectID)
	if !hasPlannedWriteTx(w.tx, origin) {
		return recordProtectionUsage(w, current, nodeID, usage)
	}
	var node types.NodeInfo
	if err := json.Unmarshal(w.tx.Bucket(bucketNodes).Get(u64be(nodeID)), &node); err != nil {
		return err
	}
	if usage.UsedBytes < current.Size {
		return ErrWritePlanConflict
	}
	if err := applyNodeUsage(&node, *usage); err != nil {
		return err
	}
	raw, err := json.Marshal(node)
	if err != nil {
		return err
	}
	if err = w.putNode(raw, nodeID); err != nil {
		return err
	}
	raw, err = json.Marshal(usage)
	if err != nil {
		return err
	}
	return w.put(bcWrites, bucketWrites, writeUsageKey(current.ObjectID, nodeID), raw)
}

func recordProtectionUsage(w *txw, current types.ObjectIntegrity, nodeID uint64, usage *types.NodeUsage) error {
	if usage == nil {
		return nil
	}
	var node types.NodeInfo
	if err := json.Unmarshal(w.tx.Bucket(bucketNodes).Get(u64be(nodeID)), &node); err != nil {
		return err
	}
	if usage.UsedBytes < current.Size {
		return ErrWritePlanConflict
	}
	if err := applyNodeUsage(&node, *usage); err != nil {
		return err
	}
	raw, err := json.Marshal(node)
	if err != nil {
		return err
	}
	if err := w.putNode(raw, nodeID); err != nil {
		return err
	}
	raw, err = json.Marshal(usage)
	if err != nil {
		return err
	}
	return w.put(bcAutonomy, bucketAutonomy, protectionUsageKey(current.ObjectID, nodeID), raw)
}

func protectionUsageKey(objectID, nodeID uint64) []byte {
	return autonomyKey("receipt", fmt.Sprintf("%d/%d", objectID, nodeID))
}

func protectionUsageCoveredTx(tx *bolt.Tx, objectID, nodeID uint64) (bool, error) {
	return nodeUsageCoveredTx(tx, tx.Bucket(bucketAutonomy).Get(protectionUsageKey(objectID, nodeID)), nodeID)
}

func writeUsageCoveredTx(tx *bolt.Tx, objectID, nodeID uint64) (bool, error) {
	return nodeUsageCoveredTx(tx, tx.Bucket(bucketWrites).Get(writeUsageKey(objectID, nodeID)), nodeID)
}

func nodeUsageCoveredTx(tx *bolt.Tx, raw []byte, nodeID uint64) (bool, error) {
	if raw == nil {
		return false, nil
	}
	var receipt types.NodeUsage
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return false, err
	}
	if !validNodeUsage(receipt) {
		return false, ErrWritePlanConflict
	}
	var node types.NodeInfo
	raw = tx.Bucket(bucketNodes).Get(u64be(nodeID))
	if raw == nil {
		return false, nil
	}
	if err := json.Unmarshal(raw, &node); err != nil {
		return false, err
	}
	return node.Usage != nil && validNodeUsage(*node.Usage) && node.UsedBytes == node.Usage.UsedBytes && node.Usage.Epoch == receipt.Epoch && node.Usage.Sequence >= receipt.Sequence, nil
}
