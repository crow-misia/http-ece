/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/cipher"
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

	// Save the DH public key in the header unless keyID is set.
	if opt.encoding == AES128GCM && len(opt.keyID) == 0 {
		opt.keyID = opt.publicKey.Bytes()
	}

	debug.dumpBinary("recv pub key", opt.dh)
	debug.dumpBinary("send prv key", opt.privateKey.Bytes())

	// Generate salt
	saltLen := len(opt.salt)
	if saltLen == 0 {
		if opt.salt, err = randomSalt(); err != nil {
			return nil, err
		}
	} else if saltLen != keyLen {
		return nil, fmt.Errorf("the salt parameter must be %d bytes", keyLen)
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
	overhead := opt.encoding.overhead(gcm)
	if opt.recordSize <= overhead {
		return nil, fmt.Errorf("recordSize has to be greater than %d", overhead)
	}

	var (
		baseRecordSize = opt.recordSize - overhead
		start          = uint32(0)
		counter        = uint32(0)
		plaintextLen   = uint32(len(plaintext))
		pad            = opt.pad
		recordNum      = 1 + (plaintextLen+pad+baseRecordSize-1)/baseRecordSize
	)

	results := make([][]byte, 0, recordNum)
	// Create header.
	results, err = writeHeader(opt, results)
	if err != nil {
		return nil, err
	}

	// Encrypt records.
	last := false
	for !last {
		recordPad := opt.encoding.calculateRecordPadSize(pad, baseRecordSize)
		pad -= recordPad
		end := start + baseRecordSize - recordPad
		last = opt.encoding.isLastBlock(pad, plaintextLen, end)
		end = min(end, plaintextLen)
		// Generate nonce.
		nonce := generateNonce(baseNonce, counter)
		debug.dumpBinary("nonce", nonce)
		r := encryptRecord(opt, gcm, nonce, plaintext[start:end], recordPad, last)
		results = append(results, r)
		debug.dumpBinary("result", r)
		start = end
		counter++
	}
	return join(results), nil
}

func encryptRecord(opt *options, gcm cipher.AEAD, nonce, plaintext []byte, recordPad uint32, last bool) []byte {
	plaintextWithPadding := opt.encoding.appendPadding(plaintext, recordPad, last)
	return gcm.Seal(nil, nonce, plaintextWithPadding, nil)
}

func writeHeader(opt *options, results [][]byte) ([][]byte, error) {
	switch opt.encoding {
	case AES128GCM:
		keyIDLen := len(opt.keyID)
		saltLen := len(opt.salt)
		buffer := make([]byte, saltLen+4+1+keyIDLen)
		copy(buffer, opt.salt)
		copy(buffer[saltLen:], uint32ToBytes(opt.recordSize))
		buffer[saltLen+4] = uint8(keyIDLen)
		copy(buffer[saltLen+5:], opt.keyID)
		return append(results, buffer), nil
	default:
		// No header on other versions
		return results, nil
	}
}
