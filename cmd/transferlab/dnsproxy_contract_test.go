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
	for _, flag := range []uint16{dnsFlagAD, dnsFlagCD} {
		if cacheableQuery(query, flags|flag, 1, 1) {
			t.Fatalf("security flag %#04x reused the ordinary cache", flag)
		}
	}
}

func TestDNSProxyQueryFlagsCacheContract(t *testing.T) {
	up := startFakeDNS(t, 50, "")
	proxy, err := startDNSProxy(up.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	for _, tc := range []struct {
		name string
		flag uint16
		want int
	}{
		{name: "ordinary", want: 1},
		{name: "authentic-data", flag: dnsFlagAD, want: 3},
		{name: "checking-disabled", flag: dnsFlagCD, want: 5},
		{name: "ordinary-still-cached", want: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, id := range []uint16{0x1010, 0x2020} {
				query := buildFakeQuery(id, "flags.et.net", 1)
				binary.BigEndian.PutUint16(query[2:4], 0x0100|tc.flag)
				binary.BigEndian.PutUint16(query[10:12], 1)
				query = append(query, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0)
				response := udpRoundtrip(t, proxy.addr(), query)
				if !validReply(response, query) || response[3]&0x0f != 0 {
					t.Fatalf("invalid response or request ID: %x", response)
				}
			}
			if got := up.count(); got != tc.want {
				t.Fatalf("upstream queries: got %d want %d", got, tc.want)
			}
			if tc.flag != 0 {
				query := up.lastQuery()
				if binary.BigEndian.Uint16(query[2:4]) != 0x0100|tc.flag {
					t.Fatal("proxy changed the query security flags")
				}
			}
		})
	}
}
