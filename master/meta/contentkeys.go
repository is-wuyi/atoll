package meta

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"atoll/pkg/contentcrypto"
	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

const contentKeyPrefix = "content-key/"

type ContentKeyRecord struct {
	ObjectID   uint64    `json:"object_id"`
	Generation uint64    `json:"generation"`
	SpaceID    uint64    `json:"space_id"`
	KeyID      string    `json:"key_id"`
	WrappedDEK string    `json:"wrapped_dek"`
	CreatedAt  time.Time `json:"created_at"`
}

func contentKeyStoreKey(objectID uint64) []byte {
	return []byte(fmt.Sprintf("%s%d", contentKeyPrefix, objectID))
}

// PrepareContentKey 为计划上传的块对象预创建 wrapped DEK。generation 是内容
// 版本身份（ContentVersion.ID = staging ID，Begin 时冻结）；块对象 ID 从它派生
// （ChunkID），因此这里按计划上传记录解析归属，不接受其他锚点。同一
// (objectID, generation, spaceID, keyID) 幂等返回既有记录；不一致一律拒绝。
func (s *Store) PrepareContentKey(userID, spaceID, objectID, generation uint64, kek *contentcrypto.KEK, now time.Time) (ContentKeyRecord, error) {
	var out ContentKeyRecord
	if kek == nil || objectID == 0 || generation == 0 || now.IsZero() {
		return out, ErrWritePlanConflict
	}
	if objectID < types.StagingInodeBase<<8 || objectID >= types.ObjectIDBase {
		return out, ErrWritePlanConflict
	}
	anchor, _ := types.ParseChunkID(objectID)
	err := s.write(func(w *txw) error {
		if anchor != generation {
			return ErrObjectChanged
		}
		if err := requireWritePlanningTx(w.tx); err != nil {
			return err
		}
		rec, err := plannedWriteTx(w.tx, anchor)
		if err != nil {
			return err
		}
		if rec.Actor != (WriteActor{UserID: userID, SpaceID: spaceID}) {
			return ErrAuthentication
		}
		if rec.Upload.State == types.WriteAborted || (rec.Upload.State == types.WritePending && !now.Before(rec.Upload.ExpiresAt)) {
			return ErrWriteExpired
		}
		staging, err := getInodeTx(w.tx, anchor)
		if err != nil {
			return err
		}
		if !staging.Staging || !staging.Chunked || staging.ParentID != rec.ParentID {
			return ErrWritePlanConflict
		}
		if err := inodeInSpaceTx(w.tx, spaceID, staging.ParentID); err != nil {
			return err
		}
		if _, err := authorizeSpaceTx(w.tx, userID, spaceID, true); err != nil {
			return err
		}
		if current, err := contentKeyTx(w.tx, objectID); err == nil {
			if current.Generation != generation || current.SpaceID != spaceID || current.KeyID != kek.KeyID() {
				return ErrObjectChanged
			}
			out = current
			return nil
		} else if !errors.Is(err, ErrNotExist) {
			return err
		}
		dek, err := contentcrypto.NewDEK()
		if err != nil {
			return err
		}
		wrapped, err := contentcrypto.WrapDEK(kek, dek, objectID)
		if err != nil {
			return err
		}
		out = ContentKeyRecord{ObjectID: objectID, Generation: generation, SpaceID: spaceID, KeyID: kek.KeyID(), WrappedDEK: base64.RawStdEncoding.EncodeToString(wrapped), CreatedAt: now}
		raw, err := json.Marshal(out)
		if err != nil {
			return err
		}
		return w.put(bcSecurity, bucketSecurity, contentKeyStoreKey(objectID), raw)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func contentKeyTx(tx *bolt.Tx, objectID uint64) (ContentKeyRecord, error) {
	var out ContentKeyRecord
	raw := tx.Bucket(bucketSecurity).Get(contentKeyStoreKey(objectID))
	if raw == nil {
		return out, ErrNotExist
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	if out.ObjectID != objectID || out.Generation == 0 || out.SpaceID == 0 || out.KeyID == "" || out.WrappedDEK == "" || out.CreatedAt.IsZero() {
		return out, ErrWritePlanConflict
	}
	return out, nil
}

func (s *Store) GetContentKey(userID, spaceID, objectID, generation uint64) (ContentKeyRecord, error) {
	var out ContentKeyRecord
	if objectID == 0 || generation == 0 {
		return out, ErrWritePlanConflict
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		if _, err := authorizeSpaceTx(tx, userID, spaceID, false); err != nil {
			return err
		}
		// 待上传的块对象还没有 inode 归属：按 (generation=ContentVersion.ID,
		// objectID=ChunkID) 直接绑定计划上传记录；发布后的对象走 inode 锚点。
		if objectID >= types.StagingInodeBase<<8 && objectID < types.ObjectIDBase {
			anchor, _ := types.ParseChunkID(objectID)
			if anchor != generation {
				return ErrObjectChanged
			}
			if hasPlannedWriteTx(tx, anchor) {
				rec, err := plannedWriteTx(tx, anchor)
				if err != nil {
					return err
				}
				if rec.Upload.State == types.WritePending || rec.Upload.State == types.WriteAborted {
					// 在途/已放弃的上传仍属上传者私有：只有 Actor 本人可取钥。
					if rec.Actor != (WriteActor{UserID: userID, SpaceID: spaceID}) {
						return ErrAuthentication
					}
					if rec.Upload.State == types.WriteAborted {
						return ErrWriteExpired
					}
				}
				// 已提交（WriteCommitted）：密钥随对象进入空间——授权完全由
				// 上面的 authorizeSpaceTx(read) 决定，团队 read/write 成员与
				// 平台管理员都可取钥。归属仍经下面的 inodeInSpaceTx 双重校验。
			} else if _, err := getInodeTx(tx, generation); err != nil {
				return err
			}
			if err := inodeInSpaceTx(tx, spaceID, anchor); err != nil {
				return err
			}
		} else {
			anchor, err := objectAnchorTx(tx, objectID)
			if err != nil {
				return err
			}
			if err := inodeInSpaceTx(tx, spaceID, anchor); err != nil {
				return err
			}
		}
		var keyErr error
		out, keyErr = contentKeyTx(tx, objectID)
		if keyErr != nil {
			return keyErr
		}
		if out.SpaceID != spaceID || out.Generation != generation {
			return ErrObjectChanged
		}
		return nil
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func (s *Store) ContentKey(objectID uint64) (ContentKeyRecord, error) {
	var out ContentKeyRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = contentKeyTx(tx, objectID)
		return err
	})
	return out, err
}
