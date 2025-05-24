/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/sha256"
	"math"
)

const (
	recordSizeDefault = 4096
	recordSizeMin     = 3
	recordSizeMax     = math.MaxInt32
	keyIdLenMax       = math.MaxUint8
	keyLen            = aes.BlockSize
	recodeSizeLen     = 4
	nonceLen          = 12
	secretLen         = sha256.Size
)

var (
	authInfo       = []byte("Content-Encoding: auth\x00")
	aesgcmInfo     = []byte("Content-Encoding: aesgcm\x00")
	aes128gcmInfo  = []byte("Content-Encoding: aes128gcm\x00")
	nonceBaseInfo  = []byte("Content-Encoding: nonce\x00")
	webPushInfo    = []byte("WebPush: info\x00")
	curveAlgorithm = []byte("P-256")
	hashAlgorithm  = sha256.New
	curve          = ecdh.P256()
)
