package meta

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atoll/pkg/types"
)

func TestCommitStagingConcurrentReplayIsAtomic(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "replace"}[replace], func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "meta.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			staging := func(size int64) types.Inode {
				t.Helper()
				in, err := s.CreateStagingFile(RootID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.AssignChunk(in.ID, 0, size, []uint64{7}, 0); err != nil {
					t.Fatal(err)
				}
				if err := s.MarkChunkDone(types.ChunkID(in.ID, 0), 7); err != nil {
					t.Fatal(err)
				}
				return in
			}
			var previous types.Inode
			if replace {
				old := staging(8)
				previous, _, _, err = s.CommitStagingFile(old.ID, "file.bin", 8)
				if err != nil {
					t.Fatal(err)
				}
			}
			in := staging(16)
			var confirmations atomic.Int32
			s.SetPostCommitHook(func(uint64, []byte) error { confirmations.Add(1); return nil })
			binding := SecureCommitBinding{OpID: "atomic-retry", Fingerprint: "fixed-request"}
			type result struct {
				inode    types.Inode
				replaced bool
				err      error
			}
			results := make([]result, 8)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range results {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					out, _, replaced, err := s.CommitStagingFile(in.ID, "file.bin", 16, binding)
					results[i] = result{out, replaced, err}
				}(i)
			}
			close(start)
			wg.Wait()
			oldReturns := 0
			for _, result := range results {
				if result.err != nil || result.inode.Staging || result.inode.Size != 16 || result.inode.ID != results[0].inode.ID || result.inode.Generation != results[0].inode.Generation {
					t.Fatalf("concurrent replay differs: %+v", result)
				}
				if result.replaced {
					oldReturns++
				}
			}
			if replace && (oldReturns != 1 || results[0].inode.ID != previous.ID || results[0].inode.Generation != previous.Generation+1) {
				t.Fatalf("replacement was applied more than once: oldReturns=%d", oldReturns)
			}
			if !replace && (oldReturns != 0 || results[0].inode.ID != in.ID || results[0].inode.Generation != 1) {
				t.Fatal("new file replay changed its identity")
			}
			if confirmations.Load() != int32(len(results)) {
				t.Fatalf("replay skipped durable confirmation: %d", confirmations.Load())
			}
			if _, _, _, err := s.CommitStagingFile(in.ID, "file.bin", 16, SecureCommitBinding{OpID: binding.OpID, Fingerprint: "different-request"}); !errors.Is(err, ErrOpConflict) {
				t.Fatalf("conflicting replay should fail: %v", err)
			}
			frames, err := s.FramesSince(0)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Open(filepath.Join(t.TempDir(), "restored.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			if err := restored.ApplyFrames(frames); err != nil {
				t.Fatal(err)
			}
			rec, ok, err := restored.GetOpResult(binding.OpID)
			if err != nil || !ok || rec.Inode.ID != results[0].inode.ID || rec.Fingerprint != binding.Fingerprint || rec.CreatedAt.After(time.Now()) {
				t.Fatalf("WAL omitted atomic replay data: %+v %v", rec, err)
			}
		})
	}
}
