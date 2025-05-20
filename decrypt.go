/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// Decrypt decrypts content data.
func Decrypt(content []byte, opts ...Option) ([]byte, error) {
	var opt *options
	var err error

	// Options
	if opt, err = parseOptions(decrypt, opts); err != nil {
		return nil, err
	}

	content = readHeader(opt, content)

	// Check Record Size
	if opt.recordSize < recordSizeMin || opt.recordSize > recordSizeMax {
		return nil, fmt.Errorf("invalid record size: %d", opt.recordSize)
	}

	debug.dumpBinary("sender public key", opt.dh)
	debug.dumpBinary("receiver private key", opt.private)

	// Derive key and nonce.
	key, baseNonce, err := deriveKeyAndNonce(opt)
	if err != nil {
		return nil, err
	}

	gcm, err := createCipher(key)
	if err != nil {
		return nil, err
	}

	// Calculate chunkSize.
	chunkSize := opt.recordSize
	start := uint32(0)
	counter := uint32(0)
	contentLen := uint32(len(content))
	if opt.encoding != AES128GCM {
		chunkSize += uint32(gcm.Overhead())
	}

	// Decrypt records.
	results := make([][]byte, (contentLen+chunkSize-1)/chunkSize)
	for start < contentLen {
		end := start + chunkSize
		if end > contentLen {
			end = contentLen
		}
		// Generate nonce.
		nonce := generateNonce(baseNonce, counter)
		debug.dumpBinary("nonce", nonce)
		r, err := decryptRecord(opt, gcm, nonce, content[start:end])
		if err != nil {
			return nil, err
		}
		results = append(results, r)
		debug.dumpBinary("result", r)
		start = end
		counter++
	}
	return join(results), nil
}

func readHeader(opt *options, content []byte) []byte {
	if opt.encoding == AES128GCM {
		baseOffset := uint32(keyLen + recodeSizeLen)
		idLen := uint32(content[baseOffset])

		opt.salt = content[0:keyLen]
		opt.recordSize = binary.BigEndian.Uint32(content[keyLen:baseOffset])
		baseOffset++
		opt.keyID = content[baseOffset : baseOffset+idLen]

		return content[baseOffset+idLen:]
	}
	return content
}

func decryptRecord(opt *options, gcm cipher.AEAD, nonce []byte, content []byte) ([]byte, error) {
	result, err := gcm.Open(nil, nonce, content, nil)
	if err != nil {
		return nil, err
	}

	switch opt.encoding {
	case AESGCM:
		return result[opt.encoding.Padding():], nil
	default:
		return result[:uint32(len(result))-opt.encoding.Padding()], nil
	}
}
