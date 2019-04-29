package internal

import (
	"crypto/elliptic"
	"crypto/sha256"
)

const (
	SizeRecordMin = 3
	SizeRecordMax = 2 ^ 31 - 1
	KeyLen        = 16
	NonceLen      = 12
	SecretLen     = 32
)

var (
	AuthInfo       = []byte("Content-Encoding: auth\x00")
	AesgcmInfo     = []byte("Content-Encoding: aesgcm\x00")
	Aes128gcmInfo  = []byte("Content-Encoding: aes128gcm\x00")
	NonceBaseInfo  = []byte("Content-Encoding: nonce\x00")
	WebPushInfo    = []byte("WebPush: info\x00")
	CurveAlgorithm = []byte("P-256")
	HashAlgorithm  = sha256.New
	Curve          = elliptic.P256()
)
