package meta

import (
	bolt "go.etcd.io/bbolt"
)

// capacitiesTx 截断了 Free；保留未截断余量才能区分空闲耗尽与超额提交。
func recoveryFreeViews(capacity []NodeCapacity) (free, unclamped map[uint64]int64) {
	free = make(map[uint64]int64, len(capacity))
	unclamped = make(map[uint64]int64, len(capacity))
	for _, item := range capacity {
		free[item.NodeID] = item.Free
		unclamped[item.NodeID] = item.Capacity - item.Accounted - item.Reserved - item.Headroom
	}
	return free, unclamped
}

// 必须按对象读取预留，不能把该节点其它对象的预留抵回。
func writeRecoveryCapacityCreditTx(tx *bolt.Tx, objectID uint64, nodes []uint64, size int64) (map[uint64]int64, error) {
	reservations, err := capacityReservationsTx(tx)
	if err != nil {
		return nil, err
	}
	credit := make(map[uint64]int64, len(nodes))
	for _, id := range nodes {
		if id == 0 || size <= 0 {
			continue
		}
		if reserved, ok := reservations[[2]uint64{objectID, id}]; ok && reserved > 0 {
			credit[id] = min(reserved, size)
		}
	}
	return credit, nil
}

func applyRecoveryPlanningCapacity(capacity []NodeCapacity, oldNodes []uint64, done map[uint64]bool, credit map[uint64]int64, size int64) []NodeCapacity {
	out := make([]NodeCapacity, len(capacity))
	copy(out, capacity)
	old := make(map[uint64]bool, len(oldNodes))
	for _, id := range oldNodes {
		old[id] = true
	}
	for i := range out {
		c := &out[i]
		if !old[c.NodeID] {
			continue
		}
		unclamped := c.Capacity - c.Accounted - c.Reserved - c.Headroom
		base := max(int64(0), unclamped)
		switch {
		case done[c.NodeID]:
			// 已完成副本：无需新写入空间，抵回修正双重计费后始终可保留。
			c.Free = min(c.Capacity, base+size)
		case credit[c.NodeID] > 0 && unclamped >= 0:
			// 未完成副本：预留继续有效且有余量支撑，重选无需新预留。
			c.Free = min(c.Capacity, base+credit[c.NodeID])
		default:
			// 未完成但超额提交，或无预留（异常）：视同新目标节点，按真实余量。
			c.Free = min(c.Capacity, base)
		}
	}
	return out
}

// RecoveryPlanningCapacity 计算恢复规划（scheduler world）使用的容量视图。
// done 为快照期已完成且未被怀疑的副本节点；size 为副本存储大小。
// 事务提交前会以同一语义重新校验，本视图仅供规划使用。
func (s *Store) RecoveryPlanningCapacity(capacity []NodeCapacity, objectID uint64, oldNodes []uint64, done []uint64, size int64) ([]NodeCapacity, error) {
	if size <= 0 {
		return nil, ErrWritePlanConflict
	}
	var credit map[uint64]int64
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		credit, err = writeRecoveryCapacityCreditTx(tx, objectID, oldNodes, size)
		return err
	})
	if err != nil {
		return nil, err
	}
	doneSet := make(map[uint64]bool, len(done))
	for _, id := range done {
		doneSet[id] = true
	}
	return applyRecoveryPlanningCapacity(capacity, oldNodes, doneSet, credit, size), nil
}
