package decrypt

import (
	"crypto/cipher"
	"crypto/elliptic"
	"encoding/binary"
	"github.com/crow-misia/http-ece"
	. "github.com/crow-misia/http-ece/internal"
	"log"
)

func Decrypt(content []byte, opts ...Option) ([]byte, error) {
	var err error

	// Options
	opt := options{
		curve:    Curve,
		encoding: http_ece.AES128GCM,
		keyLabel: CurveAlgorithm,
		rs:       4096,
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

	content = readHeader(&opt, content)

	Debug.DumpBinary("sender pub", opt.dh)
	Debug.DumpBinary("receiver pri", opt.private)

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
	contentLen := len(content)
	if opt.encoding != http_ece.AES128GCM {
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
		nonce := GenerateNonce(baseNonce, counter)
		Debug.DumpBinary("nonce", nonce)
		r, err := decryptRecord(&opt, gcm, nonce, content[start:end])
		if err != nil {
			return nil, err
		}
		results = append(results, r)
		Debug.DumpBinary("result", r)
		start = end
		counter++
	}
	return ResultsJoin(results), nil
}

func readHeader(opt *options, content []byte) []byte {
	if opt.encoding == http_ece.AES128GCM {
		idLen := int(content[20])
		opt.salt = content[0:KeyLen]
		opt.rs = int(binary.BigEndian.Uint32(content[KeyLen : KeyLen+4]))
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
	case http_ece.AESGCM:
		return result[opt.encoding.Padding():], nil
	default:
		return result[:len(result)-opt.encoding.Padding()], nil
	}
}
