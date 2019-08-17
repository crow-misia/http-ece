/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/sha256"
)

const (
	sizeRecordDefault = 4096
	sizeRecordMin     = 3
	sizeRecordMax     = 2147483647
	keyIDLenMax       = 255
	keyLen            = 16
	nonceLen          = 12
	secretLen         = 32
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
