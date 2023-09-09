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
	if opt.rs < sizeRecordMin || opt.rs > sizeRecordMax {
		return nil, fmt.Errorf("invalid record size: %d", opt.rs)
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
	chunkSize := opt.rs
	start := 0
	counter := 0
	contentLen := len(content)
	if opt.encoding != AES128GCM {
		chunkSize += gcm.Overhead()
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
	return resultsJoin(results), nil
}

func readHeader(opt *options, content []byte) []byte {
	if opt.encoding == AES128GCM {
		baseOffset := keyLen + 4
		idLen := int(content[baseOffset])

		opt.salt = content[0:keyLen]
		opt.rs = int(binary.BigEndian.Uint32(content[keyLen:baseOffset]))
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
		return result[:len(result)-opt.encoding.Padding()], nil
	}
}
