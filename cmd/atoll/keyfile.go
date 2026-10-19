package main

import (
	"flag"
	"fmt"
	"io"

	"atoll/pkg/keyfile"
)

func runContentKeyInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("content-key-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", "", "受保护的内容 KEK 文件路径")
	keyID := fs.String("key-id", "content-20261018", "内容 KEK 标识（轮换时变更）")
	if err := fs.Parse(args); err != nil || *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "用法: atoll content-key-init -path <private-key-file> [-key-id ID]")
		return 2
	}
	if _, err := keyfile.Create(*path, *keyID); err != nil {
		fmt.Fprintln(stderr, "content-key-init:", err)
		return 1
	}
	fmt.Fprintln(stdout, "created content key file", *path, "key-id", *keyID)
	return 0
}
