// Package types 定义 atoll 各角色共享的核心数据结构。
package types

import "time"

// EntryType 区分目录与文件。
type EntryType uint8

const (
	TypeDir  EntryType = 0
	TypeFile EntryType = 1
)

// Inode 是元数据的核心单元：目录树中的一个节点。
// 文件的副本位置记录在 Replicas 中，第一个元素为主副本节点。
type Inode struct {
	ID       uint64    `json:"id"`
	ParentID uint64    `json:"parent_id"`
	Name     string    `json:"name"`
	Type     EntryType `json:"type"`
	Size     int64     `json:"size"`
	Mtime    time.Time `json:"mtime"`
	// Replicas 存放持有该文件副本的节点 ID；目录恒为空。
	Replicas []uint64 `json:"replicas,omitempty"`
}

// NodeInfo 是一个存储节点的注册信息与运行状态。
type NodeInfo struct {
	ID            uint64    `json:"id"`
	Addr          string    `json:"addr"` // 客户端直连用的 host:port
	TotalBytes    int64     `json:"total_bytes"`
	UsedBytes     int64     `json:"used_bytes"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}
