package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/crow-misia/http-ece"
	"golang.org/x/crypto/hkdf"
)

type KeyConfig struct {
	Curve          elliptic.Curve           // Curve Algorithm
	Encoding       http_ece.ContentEncoding // Content Encoding
	Salt           []byte                   // Encryption Salt
	Key            []byte                   // Encryption Key data
	AuthSecret     []byte                   // Auth Secret
	Private        []byte                   // Private Key
	Dh             []byte                   // Public Key For Diffie-Hellman
	SenderPublic   []byte                   // Sender Public Key
	ReceiverPublic []byte                   // Receiver Public Key
	KeyLabel       []byte                   // Key Label
	KeyId          []byte                   // Key Identifier
	KeyMap         func([]byte) []byte      // Key Mapping Function
}

func DeriveKeyAndNonce(config *KeyConfig) (key []byte, nonce []byte, err error) {
	var keyInfo []byte
	var nonceInfo []byte
	var secret []byte
	var context []byte

	switch config.Encoding {
	case http_ece.AESGCM:
		// old
		secret, context, err = extractSecretAndContext(config)
		if err != nil {
			return
		}
		keyInfo = buildInfo(AesgcmInfo, context)
		nonceInfo = buildInfo(NonceBaseInfo, context)
		break
	case http_ece.AES128GCM:
		// latest
		secret, err = extractSecret(config)
		if err != nil {
			return
		}
		keyInfo = buildInfo(Aes128gcmInfo, nil)
		nonceInfo = buildInfo(NonceBaseInfo, nil)
		break
	default:
		err = errors.New(fmt.Sprintf("must include a Salt parameter for %s", config.Encoding.String()))
		return
	}

	Debug.DumpBinary("info aesgcm", keyInfo)
	Debug.DumpBinary("info nonce", nonceInfo)

	Debug.DumpBinary("hkdf secret", secret)
	Debug.DumpBinary("hkdf salt", config.Salt)

	prk := hkdf.Extract(HashAlgorithm, secret, config.Salt)

	Debug.DumpBinary("hkdf prk", prk)
	Debug.DumpBinary("hkdf info", keyInfo)

	key = make([]byte, KeyLen)
	_, err = hkdf.Expand(HashAlgorithm, prk, keyInfo).Read(key)
	if err != nil {
		return
	}

	Debug.DumpBinary("key", key)
	Debug.DumpBinary("hkdf prk", prk)
	Debug.DumpBinary("hkdf info", nonceInfo)

	nonce = make([]byte, NonceLen)
	_, err = hkdf.Expand(HashAlgorithm, prk, nonceInfo).Read(nonce)
	if err != nil {
		return
	}
	Debug.DumpBinary("base nonce", nonce)
	return
}

func CreateCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func extractSecretAndContext(config *KeyConfig) (secret []byte, context []byte, err error) {
	optKeyLen := len(config.Key)
	if optKeyLen > 0 {
		secret = config.Key
		if optKeyLen != KeyLen {
			err = errors.New(fmt.Sprintf("An explicit Key must be %d bytes", KeyLen))
			return
		}
		context = make([]byte, 0)
	} else if config.Private != nil {
		Debug.DumpBinary("receiver pub", config.ReceiverPublic)

		secret = ComputeSecret(config.Curve, config.Private, config.Dh)
		context = newContext(config)
	} else if config.KeyId != nil {
		secret = config.KeyMap(config.KeyId)
		context = make([]byte, 0)
	}

	if secret == nil {
		return nil, nil, errors.New("unable to determine key")
	}

	Debug.DumpBinary("secret", secret)
	Debug.DumpBinary("context", context)

	if config.AuthSecret == nil {
		return
	}

	Debug.DumpBinary("hkdf secret", secret)
	Debug.DumpBinary("hkdf salt", config.AuthSecret)
	Debug.DumpBinary("hkdf info", AuthInfo)

	authSecret := make([]byte, SecretLen)
	_, err = hkdf.New(HashAlgorithm, secret, config.AuthSecret, AuthInfo).Read(authSecret)
	if err != nil {
		return
	}
	Debug.DumpBinary("authsecret", authSecret)
	return authSecret, context, nil
}

func extractSecret(config *KeyConfig) (secret []byte, err error) {
	optKeyLen := len(config.Key)
	if optKeyLen > 0 {
		secret = config.Key
		if optKeyLen != KeyLen {
			err = errors.New(fmt.Sprintf("An explicit Key must be %d bytes", KeyLen))
		}
		return
	}
	if config.AuthSecret == nil {
		return nil, errors.New("no authentication secret for webpush")
	}

	secret = ComputeSecret(config.Curve, config.Private, config.Dh)
	authInfo := append(append(WebPushInfo, config.ReceiverPublic...), config.SenderPublic...)

	Debug.DumpBinary("hkdf ikm", secret)
	Debug.DumpBinary("hkdf salt", config.AuthSecret)
	Debug.DumpBinary("hkdf info", authInfo)

	newSecret := make([]byte, SecretLen)
	_, err = hkdf.New(HashAlgorithm, secret, config.AuthSecret, authInfo).Read(newSecret)
	if err != nil {
		return
	}
	return newSecret, nil
}

func buildInfo(base []byte, context []byte) []byte {
	baseLen := len(base)
	contextLen := len(context)
	result := make([]byte, 0, baseLen+contextLen)
	result = append(result, base...)
	if contextLen > 0 {
		result = append(result, context...)
	}
	return result
}

func newContext(config *KeyConfig) []byte {
	var ctx []byte

	if config.Encoding == http_ece.AESGCM {
		// The context format is:
		// KeyLabel || 0x00 ||
		// length(receiverPublicKey) || receiverPublicKey ||
		// length(senderPublicKey) || senderPublicKey
		// The lengths are 16-bit, Big Endian, unsigned integers so take 2 bytes each.
		keyLabelLen := len(config.KeyLabel)

		rplen := len(config.ReceiverPublic)
		rplenbuf := Uint16ToBytes(rplen)

		splen := len(config.SenderPublic)
		splenbuf := Uint16ToBytes(splen)

		ctx = make([]byte, 0, keyLabelLen+1+2+rplen+2+splen)
		ctx = append(ctx, config.KeyLabel...)
		ctx = append(ctx, 0)
		ctx = append(ctx, rplenbuf...)
		ctx = append(ctx, config.ReceiverPublic...)
		ctx = append(ctx, splenbuf...)
		ctx = append(ctx, config.SenderPublic...)
	} else {
		ctx = make([]byte, 0)
	}

	return ctx
}
