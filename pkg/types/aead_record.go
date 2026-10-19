package types

import (
	"errors"
	"math"
)

// AeadRecordEncoding 是对象密文记录编码：明文按 64KiB 定长切段（末段可短），
// 每段独立 AES-256-GCM 封装为 record(version 1) = header(17) || ciphertext||tag(16)。
// 记录在对象内顺序串接，index 按对象内顺序从 0 递增并进 AAD。
const AeadRecordEncoding = "aead-record-v1"

// AeadRecordPlaintext 与 contentcrypto.MaxRecordPlaintext 保持一致（64KiB）。
// 这里独立声明，避免 pkg/types 反向依赖 contentcrypto。
const AeadRecordPlaintext = 64 << 10

// AeadRecordOverhead 是每条记录的线格式开销：magic(4)+version(1)+nonce(12) 头
// 加 GCM tag(16)。
const AeadRecordOverhead = 33

// AeadRecordCount 返回 logical 字节按 64KiB 定长切分后的记录条数。
// logical 为 0 时没有记录；负值或溢出返回错误。
func AeadRecordCount(logical int64) (int, error) {
	if logical < 0 {
		return 0, errors.New("negative logical size")
	}
	if logical > math.MaxInt64-AeadRecordOverhead*logical/AeadRecordPlaintext {
		return 0, errors.New("logical size overflows stored size")
	}
	return int((logical + AeadRecordPlaintext - 1) / AeadRecordPlaintext), nil
}

// AeadStoredSize 返回 logical 明文经 aead-record-v1 封装后的精确存储字节数：
// 每条满 64KiB 记录增加 AeadRecordOverhead 字节。logical 为 0 时结果为 0
// （空对象不存在记录，与 plain 空对象几何一致）。
func AeadStoredSize(logical int64) (int64, error) {
	records, err := AeadRecordCount(logical)
	if err != nil {
		return 0, err
	}
	total := logical
	for i := 0; i < records; i++ {
		total += AeadRecordOverhead
		if total < 0 {
			return 0, errors.New("stored size overflow")
		}
	}
	return total, nil
}

// AeadRecordIndex 返回对象内覆盖逻辑偏移 offset 的记录序号与该记录在对象密文
// 中的起点。调用方保证 0 <= offset < logical。
func AeadRecordIndex(offset int64) (index int, storedOffset int64, err error) {
	if offset < 0 {
		return 0, 0, errors.New("negative offset")
	}
	index = int(offset / AeadRecordPlaintext)
	storedOffset = int64(index) * (AeadRecordPlaintext + AeadRecordOverhead)
	return index, storedOffset, nil
}

// AeadRecordExtent 返回第 index 条记录的密文 [start, end)（对象内偏移）与该记录
// 的明文长度。index 必须落在 recordCount 的 [0, count) 内。
func AeadRecordExtent(index int, logical int64) (start, length, plainLen int64, err error) {
	count, err := AeadRecordCount(logical)
	if err != nil {
		return 0, 0, 0, err
	}
	if index < 0 || index >= count {
		return 0, 0, 0, errors.New("record index out of range")
	}
	start = int64(index) * (AeadRecordPlaintext + AeadRecordOverhead)
	if index == count-1 {
		plainLen = logical - int64(index)*AeadRecordPlaintext
	} else {
		plainLen = AeadRecordPlaintext
	}
	return start, plainLen + AeadRecordOverhead, plainLen, nil
}

// ChunkLogicalSize 返回块在文件内容中的逻辑长度。旧块表没有 LogicalSize/Encoding
// 字段（plain 几何下物理=逻辑），统一从这里取，读取端不再直接用 c.Size 当逻辑长度。
func ChunkLogicalSize(c ChunkInfo) int64 {
	if c.LogicalSize != 0 {
		return c.LogicalSize
	}
	if c.Encoding == "" || c.Encoding == PlainEncoding {
		return c.Size
	}
	return 0
}

// ChunkEncoding 返回块的生效编码：空编码归一为 plain-v1（旧数据语义）。
func ChunkEncoding(c ChunkInfo) string {
	if c.Encoding == "" {
		return PlainEncoding
	}
	return c.Encoding
}

// ValidateChunkGeometry 按编码校验一个块的逻辑/物理长度组合。plain 要求两者
// 相等；aead-record-v1 要求存储长度恰等于 AeadStoredSize(logical)。
func ValidateChunkGeometry(encoding string, logical, stored int64) error {
	switch encoding {
	case PlainEncoding:
		if stored != logical {
			return errors.New("plain chunk stored size must equal logical size")
		}
	case AeadRecordEncoding:
		want, err := AeadStoredSize(logical)
		if err != nil {
			return err
		}
		if stored != want {
			return errors.New("aead chunk stored size does not match record layout")
		}
	default:
		return errors.New("unsupported chunk encoding")
	}
	return nil
}
