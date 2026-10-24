package main

import (
	"encoding/binary"
	"testing"
)

func TestDNSProxyRejectsNonDefaultEDNSCacheKeys(t *testing.T) {
	query := buildFakeQuery(42, "node.et.net", 1)
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0)
	flags := binary.BigEndian.Uint16(query[2:4])
	if !cacheableQuery(query, flags, 1, 1) {
		t.Fatal("default EDNS query cannot use the cache")
	}
	opt := len(query) - 11
	for _, offset := range []int{5, 6, 7, 8} {
		changed := append([]byte(nil), query...)
		changed[opt+offset] = 0x80
		if cacheableQuery(changed, flags, 1, 1) {
			t.Fatalf("non-default EDNS metadata at offset %d reused the cache", offset)
		}
	}
	changed := append(append([]byte(nil), query...), 1)
	if cacheableQuery(changed, flags, 1, 1) {
		t.Fatal("trailing EDNS data reused the cache")
	}
	if cacheableQuery(query, flags|dnsFlagCD, 1, 1) {
		t.Fatal("checking-disabled query reused the ordinary cache")
	}
}
