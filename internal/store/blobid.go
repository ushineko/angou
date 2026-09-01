package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

// NameKeyLen is the length of K_name, the blob-naming key (spec 001 R3.3).
const NameKeyLen = 32

// blobIDLen is the number of base32 characters retained from the HMAC (R3.2).
const blobIDLen = 26

// blobIDEncoding is lowercase base32 without padding, so blob names are
// case-insensitively safe on every filesystem a synced store may land on.
const blobIDAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

var blobIDEncoding = base32.NewEncoding(blobIDAlphabet).WithPadding(base32.NoPadding)

// LooksLikeBlobID reports whether a filename has the shape of a blob name.
//
// It is what separates "this file is a blob and something is wrong with it" from
// "this file is not a blob". A sync service that duplicates files leaves names
// like "index (conflicted copy 2026-08-31).angou" in the store, and a rebuild
// that treated those as damaged blobs would abort on exactly the corruption it
// exists to repair (R3.7, R-6).
func LooksLikeBlobID(name string) bool {
	if len(name) != blobIDLen {
		return false
	}
	for _, r := range name {
		if !strings.ContainsRune(blobIDAlphabet, r) {
			return false
		}
	}
	return true
}

// BlobID computes the on-disk name for a logical path:
//
//	blob_id = base32( HMAC-SHA256(K_name, normalized_path) )[:26]
//
// The name is keyed rather than a plain hash (R3.4): filenames are low-entropy,
// and an unkeyed digest would let anyone holding the store run an offline
// dictionary attack over names like ".env" or "id_rsa" and learn its contents
// without any key at all.
func BlobID(nameKey []byte, logicalPath string) (string, error) {
	if len(nameKey) != NameKeyLen {
		return "", fmt.Errorf("naming key must be %d bytes, got %d", NameKeyLen, len(nameKey))
	}
	normalized, err := NormalizePath(logicalPath)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, nameKey)
	mac.Write([]byte(normalized))
	return blobIDEncoding.EncodeToString(mac.Sum(nil))[:blobIDLen], nil
}
