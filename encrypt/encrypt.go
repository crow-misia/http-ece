package encrypt

import (
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
	"github.com/crow-misia/http-ece"
	. "github.com/crow-misia/http-ece/internal"
)

func Encrypt(plaintext []byte, opts ...Option) ([]byte, error) {
	var err error

	// Options
	opt := options{
		curve:    Curve,
		encoding: http_ece.AES128GCM,
		rs:       4096,
		keyLabel: CurveAlgorithm,
	}
	for _, o := range opts {
		o(&opt)
	}

	// Create / set sender private key.
	if opt.private == nil {
		opt.private, opt.public, err = RandomKey(opt.curve)
		if err != nil {
			return nil, err
		}
	} else {
		x, y := Curve.ScalarBaseMult(opt.private)
		opt.public = elliptic.Marshal(Curve, x, y)
	}
	Debug.DumpBinary("sender pub", opt.public)
	Debug.DumpBinary("sender pri", opt.private)

	// Generate Salt
	if len(opt.salt) == 0 {
		opt.salt, err = RandomSalt()
		if err != nil {
			return nil, err
		}
	}

	// Save the DH public key in the header unless keyId is set.
	if opt.encoding == http_ece.AES128GCM && len(opt.keyId) == 0 {
		opt.keyId = opt.public
	}

	// Derive key and nonce.
	config := opt.toKeyConfig()
	key, baseNonce, err := DeriveKeyAndNonce(config)
	if err != nil {
		return nil, err
	}

	gcm, err := CreateCipher(key)
	if err != nil {
		return nil, err
	}

	// Calculate chunkSize.
	chunkSize := opt.rs
	start := 0
	counter := 0
	plaintextLen := len(plaintext)
	chunkSize -= opt.encoding.Padding()
	if opt.encoding == http_ece.AES128GCM {
		chunkSize -= gcm.Overhead()
	}

	results := make([][]byte, 1+(plaintextLen+chunkSize-1)/chunkSize)
	// Create header.
	results, err = writeHeader(&opt, results)
	if err != nil {
		return nil, err
	}

	// Encrypt records.
	last := false
	for !last {
		end := start + chunkSize
		switch opt.encoding {
		case http_ece.AES128GCM:
			last = end >= plaintextLen
			break
		case http_ece.AESGCM:
			last = end > plaintextLen
			break
		}
		if end > plaintextLen {
			end = plaintextLen
		}
		// Generate nonce.
		nonce := GenerateNonce(baseNonce, counter)
		Debug.DumpBinary("nonce", nonce)
		r := encryptRecord(&opt, gcm, nonce, plaintext[start:end], last)
		results = append(results, r)
		Debug.DumpBinary("result", r)
		start = end
		counter++
	}
	return ResultsJoin(results), nil
}

func encryptRecord(opt *options, gcm cipher.AEAD, nonce []byte, plaintext []byte, last bool) []byte {
	plaintextWithPadding := appendPad(plaintext, opt.encoding, last)
	return gcm.Seal(nil, nonce, plaintextWithPadding, nil)
}

func appendPad(plaintext []byte, encoding http_ece.ContentEncoding, last bool) []byte {
	result := make([]byte, 0, len(plaintext)+encoding.Padding())

	switch encoding {
	case http_ece.AESGCM:
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
	case http_ece.AES128GCM:
		keyIdLen := len(opt.keyId)
		if keyIdLen > 255 {
			return nil, errors.New("keyId is too large")
		}

		buffer := make([]byte, 0, len(opt.salt)+4+1+keyIdLen)
		buffer = append(buffer, opt.salt...)
		buffer = append(buffer, Uint32ToBytes(opt.rs)...)
		buffer = append(buffer, uint8(keyIdLen))
		buffer = append(buffer, opt.keyId...)
		results = append(results, buffer)
		return results, nil
	default:
		// No header on other versions
		return results, nil
	}
}
