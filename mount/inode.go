package mount

// 挂载层 st_ino 分配：为每个集群路径维护一个稳定、唯一、与远端 inode ID 解耦的 st_ino。
//
// 为什么不直接用远端 inode ID：POSIX 要求同一文件的 inode 号在其生命周期内不变，但 atoll
// master 的两类操作与之冲突——
//   - 覆盖写（cp -f / 编辑器保存 / rsync --inplace）："建 staging → commit 原子换名 → 删旧"，
//     每次覆盖给同一路径分配全新远端 ID。若 st_ino=远端 ID，覆盖写会让 st_ino 翻转，
//     Finder/rsync 判文件被替换、拷贝不收尾。
//   - 改名：master 保留远端 ID、只改路径。若 st_ino=路径哈希，改名又会让 st_ino 翻转。
// 两者不能靠单一来源同时满足，故用一张"路径 → 本地稳定 ID"注册表：覆盖写路径不变 → ID 不变；
// 改名时把条目迁到新路径 → ID 跟随不变；删除时清除 → 删后重建视为新文件（新 ID，符合 POSIX）。
// 数据寻址走 Lookup 返回的 in.ID / 块表（与 st_ino 无关），故解耦安全。
//
// 本地 ID 从 1<<63 起单调递增，与真实 atoll ID（legacy < 2^32、块对象 ≈ staging<<8，均 <
// 2^63）互不重叠，也避开 go-fuse 保留的 ^uint64(0)（poll hack）。
const localInoBase uint64 = 1 << 63

// inoFor 返回路径的稳定 st_ino，不存在则分配一个新的（单调递增）。
func (m *Mount) inoFor(path string) uint64 {
	m.inoMu.Lock()
	defer m.inoMu.Unlock()
	if ino, ok := m.inoByPath[path]; ok {
		return ino
	}
	if m.nextIno < localInoBase {
		m.nextIno = localInoBase
	}
	ino := m.nextIno
	m.nextIno++
	m.inoByPath[path] = ino
	return ino
}

// renameIno 把 old 路径的 st_ino 迁到 new 路径（同一文件跨改名保持 inode 不变）。
func (m *Mount) renameIno(oldPath, newPath string) {
	m.inoMu.Lock()
	defer m.inoMu.Unlock()
	ino, ok := m.inoByPath[oldPath]
	if !ok {
		return
	}
	delete(m.inoByPath, oldPath)
	m.inoByPath[newPath] = ino // 覆盖旧目标条目（若有）：目标被替换，其身份让位
}

// dropIno 删除路径的 st_ino 映射（unlink/rmdir 后调用；删后重建得新 inode，符合 POSIX）。
func (m *Mount) dropIno(path string) {
	m.inoMu.Lock()
	delete(m.inoByPath, path)
	m.inoMu.Unlock()
}
