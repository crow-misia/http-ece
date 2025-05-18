/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/cipher"
	"errors"
	"fmt"
)

// Encrypt encrypts plaintext data.
func Encrypt(plaintext []byte, opts ...Option) ([]byte, error) {
	var opt *options
	var err error

	// Options
	if opt, err = parseOptions(encrypt, opts); err != nil {
		return nil, err
	}

	// Check Record Size
	if opt.recordSize < recordSizeMin || opt.recordSize > recordSizeMax {
		return nil, fmt.Errorf("invalid record size: %d", opt.recordSize)
	}

	debug.dumpBinary("receiver public key", opt.dh)
	debug.dumpBinary("sender private key", opt.private)

	// Generate salt
	saltLen := len(opt.salt)
	if saltLen == 0 {
		if opt.salt, err = randomSalt(); err != nil {
			return nil, err
		}
	} else if saltLen != keyLen {
		return nil, fmt.Errorf("the salt parameter must be %d bytes", keyLen)
	}

	// Save the DH public key in the header unless keyId is set.
	if opt.encoding == AES128GCM && len(opt.keyID) == 0 {
		opt.keyID = opt.public
	}

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
	overhead := opt.encoding.Padding()
	if opt.encoding == AES128GCM {
		overhead += uint32(gcm.Overhead())
	}
	if opt.recordSize <= overhead {
		return nil, fmt.Errorf("the rs parameter has to be greater than %d", overhead)
	}

	// Calculate chunkSize.
	chunkSize := opt.recordSize
	start := uint32(0)
	counter := uint32(0)
	plaintextLen := uint32(len(plaintext))
	chunkSize -= overhead

	results := make([][]byte, 1+(plaintextLen+chunkSize-1)/chunkSize)
	// Create header.
	results, err = writeHeader(opt, results)
	if err != nil {
		return nil, err
	}

	// Encrypt records.
	last := false
	for !last {
		end := start + chunkSize
		switch opt.encoding {
		case AES128GCM:
			last = end >= plaintextLen
			break
		case AESGCM:
			last = end > plaintextLen
			break
		}
		if end > plaintextLen {
			end = plaintextLen
		}
		// Generate nonce.
		nonce := generateNonce(baseNonce, counter)
		debug.dumpBinary("nonce", nonce)
		r := encryptRecord(opt, gcm, nonce, plaintext[start:end], last)
		results = append(results, r)
		debug.dumpBinary("result", r)
		start = end
		counter++
	}
	return resultsJoin(results), nil
}

func encryptRecord(opt *options, gcm cipher.AEAD, nonce []byte, plaintext []byte, last bool) []byte {
	plaintextWithPadding := appendPad(plaintext, opt.encoding, last)
	return gcm.Seal(nil, nonce, plaintextWithPadding, nil)
}

func appendPad(plaintext []byte, encoding ContentEncoding, last bool) []byte {
	plaintextLen := uint32(len(plaintext))
	result := make([]byte, plaintextLen+encoding.Padding())

	switch encoding {
	case AESGCM:
		copy(result, []byte{0x00, 0x00})
		copy(result[2:], plaintext)
	default:
		copy(result, plaintext)
		if last {
			result[plaintextLen] = 0x02
		} else {
			result[plaintextLen] = 0x01
		}
	}
	return result
}

func writeHeader(opt *options, results [][]byte) ([][]byte, error) {
	switch opt.encoding {
	case AES128GCM:
		keyIDLen := len(opt.keyID)
		if keyIDLen > keyIDLenMax {
			return nil, errors.New("keyId is too large")
		}

		saltLen := len(opt.salt)
		buffer := make([]byte, saltLen+4+1+keyIDLen)
		copy(buffer, opt.salt)
		copy(buffer[saltLen:], uint32ToBytes(opt.recordSize))
		buffer[saltLen+4] = uint8(keyIDLen)
		copy(buffer[saltLen+5:], opt.keyID)
		results = append(results, buffer)
		return results, nil
	default:
		// No header on other versions
		return results, nil
	}
}
