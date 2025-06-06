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

	// Derive key and nonce.
	key, baseNonce, err := deriveKeyAndNonce(opt)
	if err != nil {
		return nil, err
	}

	gcm, err := createCipher(key)
	if err != nil {
		return nil, err
	}

	// Check Record Size
	overhead := opt.encoding.overhead(gcm)
	if opt.recordSize < overhead {
		return nil, fmt.Errorf("recordSize has to be greater than %d", overhead)
	}

	// Calculate chunkSize.
	var (
		baseRecordSize = opt.recordSize - overhead
		start          = uint32(0)
		counter        = uint32(0)
		contentLen     = uint32(len(content))
		recordNum      = (contentLen + baseRecordSize - 1) / baseRecordSize
	)

	// Decrypt records.
	results := make([][]byte, 0, recordNum)
	for start < contentLen {
		end, err := opt.encoding.calculateCipherBlockEnd(gcm, start, contentLen, opt.recordSize)
		if err != nil {
			return nil, err
		}
		last := end == contentLen
		// Generate nonce.
		nonce := generateNonce(baseNonce, counter)
		debug.dumpBinary("nonce", nonce)
		r, err := decryptRecord(opt, gcm, nonce, content[start:end], last)
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

func decryptRecord(opt *options, gcm cipher.AEAD, nonce []byte, content []byte, last bool) ([]byte, error) {
	result, err := gcm.Open(nil, nonce, content, nil)
	if err != nil {
		return nil, err
	}

	return opt.encoding.unpad(result, last)
}
