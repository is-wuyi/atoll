package main

import (
	"bytes"
	"testing"
)

// 已知子命令应返回退出码 0
func TestDispatchKnownCommands(t *testing.T) {
	for _, cmd := range []string{"master", "node", "mount"} {
		var buf bytes.Buffer
		if code := dispatch(&buf, []string{cmd}); code != 0 {
			t.Errorf("dispatch(%q) = %d, want 0", cmd, code)
		}
		if buf.Len() == 0 {
			t.Errorf("dispatch(%q) 没有产生任何输出", cmd)
		}
	}
}

// 缺少参数或未知命令应返回退出码 2
func TestDispatchErrors(t *testing.T) {
	cases := [][]string{nil, {}, {"nope"}}
	for _, args := range cases {
		var buf bytes.Buffer
		if code := dispatch(&buf, args); code != 2 {
			t.Errorf("dispatch(%v) = %d, want 2", args, code)
		}
	}
}
