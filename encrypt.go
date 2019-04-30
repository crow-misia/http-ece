package http_ece

import (
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
)

func Encrypt(plaintext []byte, opts ...Option) ([]byte, error) {
	var err error

	// Options
	opt := &options{
		mode:     ENCRYPT,
		curve:    elliptic.P256(),
		encoding: AES128GCM,
		rs:       4096,
		keyLabel: curveAlgorithm,
	}
	for _, o := range opts {
		o(opt)
	}

	curve := opt.curve

	// Create / set sender private key.
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

	// Generate Salt
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
	result := make([]byte, 0, len(plaintext)+encoding.Padding())

	switch encoding {
	case AESGCM:
		result = append(result, 0x00, 0x00)
		result = append(result, plaintext...)
	default:
		result = append(result, plaintext...)
		if last {
			result = append(result, 0x02)
		} else {
			result = append(result, 0x01)
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

		buffer := make([]byte, 0, len(opt.salt)+4+1+keyIdLen)
		buffer = append(buffer, opt.salt...)
		buffer = append(buffer, uint32ToBytes(opt.rs)...)
		buffer = append(buffer, uint8(keyIdLen))
		buffer = append(buffer, opt.keyId...)
		results = append(results, buffer)
		return results, nil
	default:
		// No header on other versions
		return results, nil
	}
}
