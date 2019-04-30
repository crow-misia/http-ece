package http_ece

import (
	"crypto/sha256"
)

const (
	sizeRecordMin = 3
	sizeRecordMax = 2 ^ 31 - 1
	keyLen        = 16
	nonceLen      = 12
	secretLen     = 32
)

var (
	authInfo       = []byte("Content-Encoding: auth\x00")
	aesgcmInfo     = []byte("Content-Encoding: aesgcm\x00")
	aes128gcmInfo  = []byte("Content-Encoding: aes128gcm\x00")
	nonceBaseInfo  = []byte("Content-Encoding: nonce\x00")
	webPushInfo    = []byte("WebPush: info\x00")
	curveAlgorithm = []byte("P-256")
	hashAlgorithm  = sha256.New
)
