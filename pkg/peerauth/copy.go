package peerauth

import "bytes"

// CopyDirectory detaches slices before a resolver or connection gate retains a snapshot.
func CopyDirectory(directory Directory) Directory {
	copy := directory
	copy.Infrastructure.PublicKey = append([]byte(nil), directory.Infrastructure.PublicKey...)
	copy.Infrastructure.Addresses = append([]string{}, directory.Infrastructure.Addresses...)
	copy.Endpoints = make([]Endpoint, len(directory.Endpoints))
	for i, endpoint := range directory.Endpoints {
		copy.Endpoints[i] = CopyEndpoint(endpoint)
	}
	return copy
}

func CopyEndpoint(endpoint Endpoint) Endpoint {
	copy := endpoint
	copy.PublicKey = append([]byte(nil), endpoint.PublicKey...)
	copy.Addresses = append([]string(nil), endpoint.Addresses...)
	return copy
}

func SameBinding(a, b *Binding) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.PeerID == b.PeerID && a.Revision == b.Revision && bytes.Equal(a.PublicKey, b.PublicKey)
}
