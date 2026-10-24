package peertransport

import (
	"context"
	"testing"
)

func TestDialContextFailureReturnsNilInterface(t *testing.T) {
	d := &DialConfig{Policy: DialPolicy("invalid")}
	conn, err := d.DialContext(context.Background(), "tcp", "unused:1")
	if err == nil || conn != nil {
		t.Fatalf("failed dial returned conn=%v err=%v", conn, err)
	}
}
