package main

import (
	"bytes"
	"testing"
)

func TestWriteTransferCLIRejectsUnpairedConfiguration(t *testing.T) {
	var output bytes.Buffer
	if code := runMaster([]string{"-write-transfer-planning"}, &output); code != 1 {
		t.Fatalf("transfer without write planner accepted: code=%d %s", code, &output)
	}
	output.Reset()
	if code := runClientCmd("put", []string{"-upload-bps", "1000", "-download-bps", "0", "unused", "/unused"}, &output, &output); code != 1 {
		t.Fatalf("partial client budget accepted: code=%d %s", code, &output)
	}
}
