package master

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"atoll/master/meta"
)

func TestRecoveryLooseWALRejectsMalformedOrConflictingCopies(t *testing.T) {
	for _, scenario := range []string{"wrong_sequence", "truncated_tail", "multiple_frames", "conflicting_copies", "valid_peer_recovers"} {
		t.Run(scenario, func(t *testing.T) {
			store, _, _ := newBackupCluster(t, 1)
			seq, err := store.WALSeq()
			if err != nil {
				t.Fatal(err)
			}
			a := meta.Frame{Seq: seq + 1}
			b := meta.Frame{Seq: seq + 2}
			valid := meta.EncodeWALSegment([]meta.Frame{a})
			body := valid
			switch scenario {
			case "wrong_sequence":
				body = meta.EncodeWALSegment([]meta.Frame{b})
			case "truncated_tail", "valid_peer_recovers":
				body = []byte("torn WAL bytes")
			case "multiple_frames":
				body = meta.EncodeWALSegment([]meta.Frame{a, b})
			case "conflicting_copies":
				// 两份均可解码且序号相同，mutation 不同，不得靠种子顺序选胜者。
				if _, err := store.CreateDir(meta.RootID, "changed"); err != nil {
					t.Fatal(err)
				}
				frames, err := store.FramesSince(seq)
				if err != nil {
					t.Fatal(err)
				}
				body = meta.EncodeWALSegment(frames)
				// 本地视图必须在待收集帧之前，另开根库并使用其水位。
				old, _, _ := newBackupCluster(t, 1)
				store = old
			}
			key := fmt.Sprintf("wal-sync-%d", a.Seq)
			seedFor := func(payload []byte) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/meta-backup" {
						json.NewEncoder(w).Encode([]blobEntry{{Key: key, Size: int64(len(payload))}})
						return
					}
					if r.URL.Path == "/meta-backup/"+key {
						w.Write(payload)
						return
					}
					http.NotFound(w, r)
				}))
			}
			seed := seedFor(body)
			defer seed.Close()
			seeds := []string{strings.TrimPrefix(seed.URL, "http://")}
			if scenario == "conflicting_copies" || scenario == "valid_peer_recovers" {
				peer := seedFor(valid)
				defer peer.Close()
				seeds = append(seeds, strings.TrimPrefix(peer.URL, "http://"))
			}
			backup := NewMetaBackup(nil, time.Hour, DefaultMetaBackupConfig())
			frames, err := backup.gatherAllFramesAfter(Manifest{SnapshotSeq: seq}, store, seeds)
			if scenario == "valid_peer_recovers" {
				if err != nil || len(frames) != 1 || frames[0].Seq != a.Seq {
					t.Fatalf("valid copy not selected: frames=%v err=%v", frames, err)
				}
			} else if err == nil {
				t.Fatalf("invalid/ambiguous loose WAL accepted: %v", frames)
			}
		})
	}
}
