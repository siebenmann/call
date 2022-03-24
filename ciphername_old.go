// Provide a mapping from uint16 cipher IDs to names, using only our
// mapping table for Go versions before Go 1.14, which don't have
// tls.CipherSuiteName()
//
//go:build !go1.14
// +build !go1.14

package main

import "fmt"

func cipherSuiteName(id uint16) string {
	cname, ok := cipherNames[id]
	if !ok {
		cname = fmt.Sprintf("cipher 0x%04x", id)
	}
	return cname
}
