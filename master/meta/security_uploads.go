package meta

import (
	"errors"
	"time"

	"atoll/pkg/types"
	bolt "go.etcd.io/bbolt"
)

type SecureCommitBinding struct {
	OpID        string
	Fingerprint string
}

type SecureUpload struct {
	InodeID          uint64    `json:"inode_id"`
	UserID           uint64    `json:"user_id"`
	SpaceID          uint64    `json:"space_id"`
	ParentID         uint64    `json:"parent_id"`
	Name             string    `json:"name"`
	TargetID         uint64    `json:"target_id"`
	TargetGeneration uint64    `json:"target_generation"`
	Overwrite        bool      `json:"overwrite"`
	CreatedAt        time.Time `json:"created_at"`
}

func secureUploadTx(tx *bolt.Tx, id uint64) (SecureUpload, error) {
	var out SecureUpload
	err := readSecurityData(tx, "upload", fmtUint(id), &out)
	return out, err
}

func (s *Store) CreateSecureUpload(userID, spaceID, parentID uint64, name string, overwrite bool, now time.Time) (types.Inode, error) {
	var out types.Inode
	if err := validateName(name); err != nil {
		return out, err
	}
	err := s.write(func(w *txw) error {
		if _, err := authorizeSpaceTx(w.tx, userID, spaceID, true); err != nil {
			return err
		}
		if err := inodeInSpaceTx(w.tx, spaceID, parentID); err != nil {
			return err
		}
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		u := SecureUpload{UserID: userID, SpaceID: spaceID, ParentID: parentID, Name: name, Overwrite: overwrite, CreatedAt: now}
		if raw := w.tx.Bucket(bucketChildren).Get(childKey(parentID, name)); raw != nil {
			current, err := getInodeTx(w.tx, beU64(raw))
			if err != nil {
				return err
			}
			if !overwrite || current.Type == types.TypeDir {
				return ErrExist
			}
			u.TargetID = current.ID
			u.TargetGeneration = current.Generation
		}
		id, err := w.nextStagingID()
		if err != nil {
			return err
		}
		out = types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeFile, Staging: true, Chunked: true, Mtime: now}
		u.InodeID = id
		if err := w.putInode(&out); err != nil {
			return err
		}
		return putSecurityData(w, "upload", fmtUint(id), u)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, err
}

func (s *Store) AuthorizeSecureUpload(userID, spaceID, inodeID uint64) (SecureUpload, error) {
	var out SecureUpload
	err := s.db.View(func(tx *bolt.Tx) error {
		if _, err := authorizeSpaceTx(tx, userID, spaceID, true); err != nil {
			return err
		}
		var err error
		out, err = secureUploadTx(tx, inodeID)
		if err != nil {
			return ErrAuthentication
		}
		if out.UserID != userID || out.SpaceID != spaceID {
			return ErrAuthentication
		}
		in, err := getInodeTx(tx, inodeID)
		if err != nil {
			return err
		}
		if !in.Staging || !in.Chunked || in.ParentID != out.ParentID {
			return ErrNotStaging
		}
		return inodeInSpaceTx(tx, spaceID, inodeID)
	})
	return out, err
}

func (s *Store) CreateSecureEmpty(userID, spaceID, parentID uint64, name string, overwrite bool, now time.Time) (types.Inode, types.Inode, bool, error) {
	var out, old types.Inode
	replaced := false
	if err := validateName(name); err != nil {
		return out, old, false, err
	}
	err := s.write(func(w *txw) error {
		if _, err := authorizeSpaceTx(w.tx, userID, spaceID, true); err != nil {
			return err
		}
		if err := inodeInSpaceTx(w.tx, spaceID, parentID); err != nil {
			return err
		}
		parent, err := getInodeTx(w.tx, parentID)
		if err != nil {
			return err
		}
		if parent.Type != types.TypeDir {
			return ErrNotDir
		}
		if raw := w.tx.Bucket(bucketChildren).Get(childKey(parentID, name)); raw != nil {
			old, err = getInodeTx(w.tx, beU64(raw))
			if err != nil {
				return err
			}
			if !overwrite || old.Type == types.TypeDir {
				return ErrExist
			}
			if err := w.delInode(old.ID); err != nil {
				return err
			}
			replaced = true
		}
		id, err := w.nextID(keyNextInode)
		if err != nil {
			return err
		}
		out = types.Inode{ID: id, ParentID: parentID, Name: name, Type: types.TypeFile, Generation: 1, Mtime: now}
		if err := w.putInode(&out); err != nil {
			return err
		}
		return w.putChild(parentID, name, id)
	})
	if err == nil {
		err = s.EnsureDurable()
	}
	return out, old, replaced, err
}

func validateSecureUploadPublish(w *txw, in types.Inode, name string) error {
	u, err := secureUploadTx(w.tx, in.ID)
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if name != u.Name || in.ParentID != u.ParentID {
		return ErrAuthentication
	}
	if _, err := authorizeSpaceTx(w.tx, u.UserID, u.SpaceID, true); err != nil {
		return err
	}
	if err := inodeInSpaceTx(w.tx, u.SpaceID, in.ParentID); err != nil {
		return err
	}
	raw := w.tx.Bucket(bucketChildren).Get(childKey(in.ParentID, name))
	if raw == nil {
		if u.TargetID != 0 {
			return ErrObjectChanged
		}
		return nil
	}
	current, err := getInodeTx(w.tx, beU64(raw))
	if err != nil {
		return err
	}
	if !u.Overwrite || current.Type == types.TypeDir || current.ID != u.TargetID || current.Generation != u.TargetGeneration {
		return ErrObjectChanged
	}
	return nil
}
