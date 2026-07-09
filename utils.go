/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"log"
)

const maxInt = int(^uint(0) >> 1)

const debug = debugT(false)

type debugT bool

func (d debugT) dumpBinary(base string, data []byte) {
	if d {
		log.Printf("%12s [%4d]: %s\n", base, len(data), base64.StdEncoding.EncodeToString(data))
	}
}

func (d debugT) dumpInfo(base string, data string) {
	if d {
		log.Printf("%12s [%4d]: %s\n", base, len(data), base64.StdEncoding.EncodeToString([]byte(data)))
	}
}

func parseOptions(mode mode, opts []Option) (*options, error) {
	opt := &options{
		mode:       mode,
		encoding:   AES128GCM,
		recordSize: recordSizeDefault,
		keyLabel:   curveAlgorithm,
		keyMap:     func(bytes []byte) []byte { return nil },
	}

	var err error
	for _, o := range opts {
		if err = o(opt); err != nil {
			return nil, err
		}
	}

	if err = opt.initialize(); err != nil {
		return nil, err
	}

	return opt, nil
}

func uint16ToBytes(i uint16) []byte {
	x := make([]byte, 2)
	binary.BigEndian.PutUint16(x, i)
	return x
}

func generateNonce(baseNonce []byte, counter uint32) []byte {
	x := make([]byte, nonceLen)
	binary.BigEndian.PutUint32(x[8:], counter)
	for i := 0; i < nonceLen; i++ {
		x[i] ^= baseNonce[i]
	}
	return x
}

func join(s [][]byte) []byte {
	return bytes.Join(s, nil)
}

func randomSalt() ([]byte, error) {
	salt := make([]byte, keyLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
