// Provide a mapping from uint16 cipher IDs to names, using either our
// mapping table or the native Go 1.14+ function for this.
//
//go:build go1.14
// +build go1.14

package main

import "crypto/tls"

// cipherSuiteName returns the name of a cipher suite, using our
// mapping table or tls.CipherSuiteName() if our mapping table lacks
// the suite.
func cipherSuiteName(id uint16) string {
	if cname, ok := cipherNames[id]; ok {
		return cname
	}
	return tls.CipherSuiteName(id)
}
