package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 帮助与未知命令
func TestRunUsage(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"help"}, &out, &errBuf); code != 0 {
		t.Fatalf("help 退出码 = %d", code)
	}
	if !strings.Contains(out.String(), "atoll master") {
		t.Fatalf("帮助文本应包含命令列表: %q", out.String())
	}
	if code := run(nil, &out, &errBuf); code != 2 {
		t.Fatalf("空参数退出码 = %d, want 2", code)
	}
	if code := run([]string{"nope"}, &out, &errBuf); code != 2 {
		t.Fatalf("未知命令退出码 = %d, want 2", code)
	}
}

// 客户端命令参数缺失应返回 2 且不发起网络请求（master 不可达也不会卡住）
func TestClientCmdArgErrors(t *testing.T) {
	cases := [][]string{
		{"put"}, {"put", "only-one"},
		{"get"}, {"get", "only-one"},
		{"ls"},
		{"mkdir"},
		{"rm"},
	}
	for _, args := range cases {
		var out, errBuf bytes.Buffer
		if code := run(args, &out, &errBuf); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
		if !strings.Contains(errBuf.String(), "用法") {
			t.Errorf("run(%v) 应输出用法, got %q", args, errBuf.String())
		}
	}
}

// flag 解析失败（如 -master 后没值）
func TestBadFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"ls", "-master"}, &out, &errBuf); code != 2 {
		t.Fatalf("坏 flag 退出码 = %d, want 2", code)
	}
}

// put 到不可达的 master 应返回 1（快速失败，不 panic）
func TestPutUnreachableMaster(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "f.txt")
	os.WriteFile(local, []byte("x"), 0o644)
	var out, errBuf bytes.Buffer
	code := run([]string{"put", "-master", "http://127.0.0.1:1", local, "/a.txt"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("put 不可达 master 退出码 = %d, want 1", code)
	}
	if !strings.Contains(errBuf.String(), "失败") {
		t.Fatalf("应输出失败信息: %q", errBuf.String())
	}
}
