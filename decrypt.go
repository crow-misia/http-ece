package http_ece

import (
	"crypto/cipher"
	"crypto/elliptic"
	"encoding/binary"
	"log"
)

func Decrypt(content []byte, opts ...Option) ([]byte, error) {
	var err error

	// Options
	opt := parseOptions(DECRYPT, opts)
	curve := opt.curve

	// Create or Set receiver private key.
	if opt.private == nil {
		opt.private, opt.public, err = randomKey(opt.curve)
		if err != nil {
			return nil, err
		}
	} else {
		x, y := curve.ScalarBaseMult(opt.private)
		opt.public = elliptic.Marshal(curve, x, y)
	}

	content = readHeader(opt, content)

	debug.dumpBinary("sender pub", opt.dh)
	debug.dumpBinary("receiver pri", opt.private)

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
		idLen := int(content[20])
		opt.salt = content[0:keyLen]
		opt.rs = int(binary.BigEndian.Uint32(content[keyLen : keyLen+4]))
		opt.keyId = content[21 : 21+idLen]
		return content[21+idLen:]
	}
	return content
}

func decryptRecord(opt *options, gcm cipher.AEAD, nonce []byte, content []byte) ([]byte, error) {
	result, err := gcm.Open(nil, nonce, content, nil)
	if err != nil {
		log.Panic(err)
		return nil, err
	}

	switch opt.encoding {
	case AESGCM:
		return result[opt.encoding.Padding():], nil
	default:
		return result[:len(result)-opt.encoding.Padding()], nil
	}
}
