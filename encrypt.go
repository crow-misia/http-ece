package http_ece

import (
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
)

func Encrypt(plaintext []byte, opts ...Option) ([]byte, error) {
	var err error

	// Options
	opt := parseOptions(ENCRYPT, opts)
	curve := opt.curve

	// Create or Set sender private key.
	if opt.private == nil {
		opt.private, opt.public, err = randomKey(curve)
		if err != nil {
			return nil, err
		}
	} else {
		x, y := curve.ScalarBaseMult(opt.private)
		opt.public = elliptic.Marshal(curve, x, y)
	}

	debug.dumpBinary("sender pub", opt.public)
	debug.dumpBinary("sender pri", opt.private)

	// Generate salt
	if len(opt.salt) == 0 {
		opt.salt, err = randomSalt()
		if err != nil {
			return nil, err
		}
	}

	// Save the DH public key in the header unless keyId is set.
	if opt.encoding == AES128GCM && len(opt.keyId) == 0 {
		opt.keyId = opt.public
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

	// Calculate chunkSize.
	chunkSize := opt.rs
	start := 0
	counter := 0
	plaintextLen := len(plaintext)
	chunkSize -= opt.encoding.Padding()
	if opt.encoding == AES128GCM {
		chunkSize -= gcm.Overhead()
	}

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
	plaintextLen := len(plaintext)
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
		keyIdLen := len(opt.keyId)
		if keyIdLen > 255 {
			return nil, errors.New("keyId is too large")
		}

		saltLen := len(opt.salt)
		buffer := make([]byte, saltLen+4+1+keyIdLen)
		copy(buffer, opt.salt)
		copy(buffer[saltLen:], uint32ToBytes(opt.rs))
		buffer[saltLen+4] = uint8(keyIdLen)
		copy(buffer[saltLen+5:], opt.keyId)
		results = append(results, buffer)
		return results, nil
	default:
		// No header on other versions
		return results, nil
	}
}
