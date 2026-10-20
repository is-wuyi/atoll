package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"atoll/master/meta"
	"atoll/pkg/keyfile"
	"atoll/pkg/types"
)

func nowForTest() time.Time { return time.Now() }

// countRecords 重新导出一次包来数记录数（避免为测试在 meta 里加列举接口）。
func countRecords(s *meta.Store) (int, error) {
	var buf bytes.Buffer
	info, err := s.ExportKeyPack(&buf, "cli-kek", nowForTest())
	return info.RecordCount, err
}

// setupKeyPackFixture 造一个带内容密钥的库 + KEK 文件，返回 (库路径, KEK 路径)。
func setupKeyPackFixture(t *testing.T) (dbPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "meta.db")
	s, err := meta.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user, space, err := s.BootstrapSecurity("admin", "pack-cli-password-123", nowForTest())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableWritePlanning(); err != nil {
		t.Fatal(err)
	}
	u, err := s.BeginPlannedWrite(meta.WriteActor{UserID: user.ID, SpaceID: space.ID}, space.RootID, "f",
		types.BeginWriteRequest{Path: "/f", OpID: "op-f", Size: 4, Overwrite: false}, nowForTest())
	if err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(keyDir, "master.key")
	if _, err := keyfile.Create(keyPath, "cli-kek"); err != nil {
		t.Fatal(err)
	}
	kek, err := keyfile.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareContentKey(user.ID, space.ID, types.ChunkID(u.ID, 0), u.ID, kek, nowForTest()); err != nil {
		t.Fatal(err)
	}
	return dbPath, keyPath
}

// TestKeyPackCLIExportImport 校验 keypack CLI 全链路：export 出包、import 到
// 全新库、重复 import 幂等、篡改被拒、缺参/覆盖拒绝。
func TestKeyPackCLIExportImport(t *testing.T) {
	dbPath, keyPath := setupKeyPackFixture(t)
	dir := t.TempDir()
	pack := filepath.Join(dir, "pack.bin")

	var out, errBuf bytes.Buffer
	if code := run([]string{"keypack", "export", "-db", dbPath, "-key-file", keyPath, "-out", pack}, &out, &errBuf); code != 0 {
		t.Fatalf("export code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}
	var exported map[string]any
	if err := json.Unmarshal(out.Bytes(), &exported); err != nil || exported["key_id"] != "cli-kek" || exported["record_count"] != float64(1) {
		t.Fatalf("export summary: %v %v", exported, err)
	}
	if _, err := os.Stat(pack); err != nil {
		t.Fatalf("pack not written: %v", err)
	}
	// 拒绝覆盖。
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"keypack", "export", "-db", dbPath, "-key-file", keyPath, "-out", pack}, &out, &errBuf); code == 0 {
		t.Fatal("overwrite export accepted")
	}

	// 导入到全新库：重建出同样记录。
	db2 := filepath.Join(dir, "restored.db")
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"keypack", "import", "-db", db2, "-in", pack, "-key-file", keyPath}, &out, &errBuf); code != 0 {
		t.Fatalf("import code=%d err=%q", code, errBuf.String())
	}
	var imported map[string]any
	if err := json.Unmarshal(out.Bytes(), &imported); err != nil || imported["imported"] != float64(1) {
		t.Fatalf("import summary: %v %v", imported, err)
	}
	s2, err := meta.Open(db2)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := countRecords(s2); err != nil || got != 1 {
		t.Fatalf("restored records: %d %v", got, err)
	}
	s2.Close()
	// 幂等重放。
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"keypack", "import", "-db", db2, "-in", pack, "-key-file", keyPath}, &out, &errBuf); code != 0 {
		t.Fatalf("replay import code=%d err=%q", code, errBuf.String())
	}
	var replay map[string]any
	if err := json.Unmarshal(out.Bytes(), &replay); err != nil || replay["unchanged"] != float64(1) || replay["imported"] != float64(0) {
		t.Fatalf("replay summary: %v %v", replay, err)
	}

	// 篡改包 → 拒绝。
	raw, _ := os.ReadFile(pack)
	tampered := append([]byte(nil), raw...)
	tampered[30] ^= 0x20
	tamperedPath := filepath.Join(dir, "tampered.bin")
	os.WriteFile(tamperedPath, tampered, 0o600)
	errBuf.Reset()
	if code := run([]string{"keypack", "import", "-db", db2, "-in", tamperedPath, "-key-file", keyPath}, &out, &errBuf); code == 0 {
		t.Fatal("tampered pack imported")
	}
	// 缺参 → 用法错误。
	if code := run([]string{"keypack", "import", "-db", db2}, &out, &errBuf); code != 2 {
		t.Fatalf("missing -in code=%d", code)
	}
	if code := run([]string{"keypack"}, &out, &errBuf); code != 2 {
		t.Fatalf("bare keypack code=%d", code)
	}
}
