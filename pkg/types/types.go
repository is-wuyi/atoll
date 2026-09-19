// Package types 定义 atoll 各角色共享的核心数据结构。
package types

import (
	"hash"
	"hash/crc32"
	"time"
)

// crcTable 是 CRC32C（Castagnoli）查表，硬件加速。用于检测静默数据损坏
// （磁盘位翻转、传输撕裂）——非加密用途，不防篡改。
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// CRC32C 计算字节切片的 CRC32C 校验和。
func CRC32C(b []byte) uint32 { return crc32.Checksum(b, crcTable) }

// NewCRC32C 返回一个流式 CRC32C hash（边写边算，用于不便整块驻留内存的路径）。
func NewCRC32C() hash.Hash32 { return crc32.New(crcTable) }

// ContainsUint64 判断 v 是否在 list 中（各角色共用，取代此前 4 处重复实现）。
func ContainsUint64(list []uint64, v uint64) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ChecksumHeader 是客户端 PUT/节点 replicate 携带期望 CRC32C 的 HTTP 头。
// 存在则节点落盘后校验；缺失则跳过（向后兼容旧客户端）。
const ChecksumHeader = "X-Atoll-Crc32c"

// EntryType 区分目录与文件。
type EntryType uint8

const (
	TypeDir  EntryType = 0
	TypeFile EntryType = 1
)

// Inode 是元数据的核心单元：目录树中的一个节点。
// 文件的副本位置记录在 Replicas 中，第一个元素为主副本。
type Inode struct {
	ID       uint64    `json:"id"`
	ParentID uint64    `json:"parent_id"`
	Name     string    `json:"name"`
	Type     EntryType `json:"type"`
	Size     int64     `json:"size"`
	Mtime    time.Time `json:"mtime"`
	// Replicas 存放该文件的目标副本节点 ID（第一个为主副本）；目录恒为空。
	// Chunked=true 的新模型文件不再使用该字段（副本在 Chunks 里）。
	Replicas []uint64 `json:"replicas,omitempty"`
	// DoneReplicas 已确认落盘完成的副本节点 ID（含主副本）。
	// 异步复制期间 DoneReplicas 是 Replicas 的子集；读操作优先从中挑选。
	DoneReplicas []uint64 `json:"done_replicas,omitempty"`
	// Staging=true 表示写入中的隐藏 inode：不挂 children，路径不可见。
	// 客户端 commit 时单事务原子换名；崩溃残留由 TTL 回收。
	Staging bool `json:"staging,omitempty"`
	// Chunked=true 表示分块存储模型（64MB 固定块）；false = 旧整文件模型。
	// 分块文件的副本位置在 Chunks 里；旧文件永久可读，不迁移。
	Chunked bool `json:"chunked,omitempty"`
	// Chunks 是分块文件（Chunked=true）的块表，按 Index 升序。
	Chunks []ChunkInfo `json:"chunks,omitempty"`
	// Checksum 是 legacy 整对象文件内容的 CRC32C（0 = 未记录）。
	// 分块文件不用此字段（校验和在每块的 ChunkInfo.Checksum 里）。
	Checksum uint32 `json:"checksum,omitempty"`
}

// ChunkInfo 是分块文件的一个块。
type ChunkInfo struct {
	Index int `json:"index"`
	// Size 块实际字节数（末块可以小于 ChunkSize）。
	Size int64 `json:"size"`
	// Replicas 该块的目标副本节点 ID（第一个为主副本）。
	Replicas []uint64 `json:"replicas"`
	// Done 已确认落盘的副本节点 ID（含主副本），是 Replicas 的子集。
	Done []uint64 `json:"done,omitempty"`
	// Checksum 块内容的 CRC32C（0 = 未记录，旧数据向后兼容跳过校验）。
	// 读取时逐块比对，不符则故障转移——检测磁盘/传输静默损坏。
	Checksum uint32 `json:"checksum,omitempty"`
}

// ---- 分块常量与 ChunkID 编解码 ----
//
// ChunkID = (stagingInodeID << 8) | index。node 侧把它当作普通 uint64 对象 ID，
// 一切块语义由 master+client 单方解释——node 零改动部署的关键。
//
// ID 空间划分（保证三类 ID 互不冲突，master 解析无需猜测）：
//   - legacy 文件 inode：计数器自增，实际规模 << 2^32
//   - staging/分块 inode：独立计数器，从 2^32 起（StagingInodeBase）
//   - 块对象 ID：stagingInodeID << 8 | index ≥ 2^40

const (
	// MaxChunksPerFile 单文件块数上限（index 编码位宽 8bit）。
	MaxChunksPerFile = 1 << 8
	// StagingInodeBase 是 staging inode ID 的起始基数（独立于 legacy 计数器）。
	StagingInodeBase uint64 = 1 << 32
	// chunkIndexBits 是 index 在 ChunkID 中占的低位位数。
	chunkIndexBits = 8
)

// ChunkSize 是分块文件的固定块大小：64MB。
// 声明为 var（而非 const）以便测试注入更小的块尺寸，构造真实的多块链路——
// 生产运行时不修改。单文件容量上限 = ChunkSize × MaxChunksPerFile（默认 16 GiB）。
var ChunkSize int64 = 64 << 20

// ChunkID 把 staging inode ID 与块下标编码为 node 侧的对象 ID。
func ChunkID(inodeID uint64, index int) uint64 {
	return (inodeID << chunkIndexBits) | uint64(index)
}

// ParseChunkID 从对象 ID 反解出 inode ID 与块下标。
func ParseChunkID(id uint64) (inodeID uint64, index int) {
	return id >> chunkIndexBits, int(id & ((1 << chunkIndexBits) - 1))
}

// NodeInfo 是一个存储节点的注册信息与运行状态。
type NodeInfo struct {
	ID            uint64    `json:"id"`
	Addr          string    `json:"addr"` // 客户端直连用的 host:port
	TotalBytes    int64      `json:"total_bytes"`
	UsedBytes     int64      `json:"used_bytes"`
	LastHeartbeat time.Time  `json:"last_heartbeat"`
}
