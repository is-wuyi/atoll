package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"atoll/master/meta"
	"atoll/pkg/keyfile"
)

// runKeyPack 离线管理内容密钥恢复包（Master 停止时对本地库操作）：
//
//	atoll keypack export -db <库> -key-file <KEK 文件> -out <恢复包路径>
//	atoll keypack import -db <库> -in <恢复包路径> [-key-file <KEK 文件>]
//
// export 用 KEK 的 keyID 做完整性绑定（不读密钥字节进内存之外的计算），
// import 带同一 KEK 文件时先校验 HMAC 再落库。
func runKeyPack(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "用法: atoll keypack export|import ...")
		return 2
	}
	switch args[0] {
	case "export":
		return runKeyPackExport(args[1:], stdout, stderr)
	case "import":
		return runKeyPackImport(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "用法: atoll keypack export|import ...")
		return 2
	}
}

func runKeyPackExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keypack export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "atoll.db", "本地元数据库（Master 停止时导出）")
	keyFile := fs.String("key-file", "", "当前 KEK 文件（atoll content-key-init 创建）")
	out := fs.String("out", "", "恢复包输出路径（拒绝覆盖已有文件）")
	if err := fs.Parse(args); err != nil || *db == "" || *keyFile == "" || *out == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "用法: atoll keypack export -db <库> -key-file <KEK> -out <恢复包>")
		return 2
	}
	kek, err := keyfile.Load(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintln(stderr, "keypack export: 输出已存在，拒绝覆盖:", *out)
		return 1
	} else if !os.IsNotExist(err) {
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	store, err := meta.Open(*db)
	if err != nil {
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	defer store.Close()
	tmp := *out + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	keep := false
	defer func() {
		if !keep {
			os.Remove(tmp)
		}
	}()
	info, err := store.ExportKeyPack(f, kek.KeyID(), time.Now())
	if err != nil {
		f.Close()
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	if err := f.Sync(); err != nil {
		f.Close()
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	if err := os.Rename(tmp, *out); err != nil {
		fmt.Fprintln(stderr, "keypack export:", err)
		return 1
	}
	keep = true
	_ = json.NewEncoder(stdout).Encode(map[string]any{
		"key_id": info.KeyID, "record_count": info.RecordCount, "size": info.Size, "path": *out,
	})
	return 0
}

func runKeyPackImport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keypack import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "atoll.db", "本地元数据库（Master 停止时导入）")
	in := fs.String("in", "", "恢复包路径")
	keyFile := fs.String("key-file", "", "当前 KEK 文件；提供则先校验包完整性")
	if err := fs.Parse(args); err != nil || *db == "" || *in == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "用法: atoll keypack import -db <库> -in <恢复包> [-key-file <KEK>]")
		return 2
	}
	f, err := os.Open(*in)
	if err != nil {
		fmt.Fprintln(stderr, "keypack import:", err)
		return 1
	}
	defer f.Close()
	verifyKeyID := ""
	if *keyFile != "" {
		kek, err := keyfile.Load(*keyFile)
		if err != nil {
			fmt.Fprintln(stderr, "keypack import:", err)
			return 1
		}
		verifyKeyID = kek.KeyID()
	}
	header, records, err := meta.ReadKeyPack(f, verifyKeyID)
	if err != nil {
		fmt.Fprintln(stderr, "keypack import:", err)
		return 1
	}
	// 护栏：记录 keyID 与本机 KEK 不一致整包拒绝——防止拿错 KEK 文件的包
	// 导入"成功"而实际内容不可解。无 key-file 时无法校验（已在上面提示）。
	if verifyKeyID != "" && header.KeyID != verifyKeyID {
		fmt.Fprintf(stderr, "keypack import: 包属于 keyID %q，与本机 KEK %q 不一致，拒绝导入\n", header.KeyID, verifyKeyID)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "keypack import:", err)
		return 1
	}
	if verifyKeyID == "" {
		fmt.Fprintln(stderr, "keypack import: 未提供 -key-file，跳过完整性校验（不能排除包被篡改或来自其他 KEK）")
	}
	store, err := meta.Open(*db)
	if err != nil {
		fmt.Fprintln(stderr, "keypack import:", err)
		return 1
	}
	defer store.Close()
	imported, unchanged, err := store.ImportKeyPack(records, header.CreatedAt, verifyKeyID)
	if err != nil {
		fmt.Fprintln(stderr, "keypack import:", err)
		return 1
	}
	_ = json.NewEncoder(stdout).Encode(map[string]any{
		"key_id": header.KeyID, "imported": imported, "unchanged": unchanged,
	})
	return 0
}
