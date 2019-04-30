package http_ece

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
)

func deriveKeyAndNonce(opt *options) (key []byte, nonce []byte, err error) {
	var keyInfo []byte
	var nonceInfo []byte
	var secret []byte
	var context []byte

	switch opt.encoding {
	case AESGCM:
		// old
		secret, context, err = extractSecretAndContext(opt)
		if err != nil {
			return
		}
		keyInfo = buildInfo(aesgcmInfo, context)
		nonceInfo = buildInfo(nonceBaseInfo, context)
		break
	case AES128GCM:
		// latest
		secret, err = extractSecret(opt)
		if err != nil {
			return
		}
		keyInfo = buildInfo(aes128gcmInfo, nil)
		nonceInfo = buildInfo(nonceBaseInfo, nil)
		break
	default:
		err = errors.New(fmt.Sprintf("must include a Salt parameter for %s", opt.encoding.String()))
		return
	}

	debug.dumpBinary("info aesgcm", keyInfo)
	debug.dumpBinary("info nonce", nonceInfo)

	debug.dumpBinary("hkdf secret", secret)
	debug.dumpBinary("hkdf salt", opt.salt)

	prk := hkdf.Extract(hashAlgorithm, secret, opt.salt)

	debug.dumpBinary("hkdf prk", prk)
	debug.dumpBinary("hkdf info", keyInfo)

	key = make([]byte, keyLen)
	_, err = hkdf.Expand(hashAlgorithm, prk, keyInfo).Read(key)
	if err != nil {
		return
	}

	debug.dumpBinary("key", key)
	debug.dumpBinary("hkdf prk", prk)
	debug.dumpBinary("hkdf info", nonceInfo)

	nonce = make([]byte, nonceLen)
	_, err = hkdf.Expand(hashAlgorithm, prk, nonceInfo).Read(nonce)
	if err != nil {
		return
	}
	debug.dumpBinary("base nonce", nonce)
	return
}

func createCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func extractSecretAndContext(opt *options) (secret []byte, context []byte, err error) {
	optKeyLen := len(opt.key)
	if optKeyLen > 0 {
		secret = opt.key
		if optKeyLen != keyLen {
			err = errors.New(fmt.Sprintf("An explicit Key must be %d bytes", keyLen))
			return
		}
		context = make([]byte, 0)
	} else if opt.private != nil {
		debug.dumpBinary("receiver pub", opt.public)

		secret = computeSecret(opt.curve, opt.private, opt.dh)
		context = newContext(opt)
	} else if opt.keyId != nil {
		secret = opt.keyMap(opt.keyId)
		context = make([]byte, 0)
	}

	if secret == nil {
		return nil, nil, errors.New("unable to determine key")
	}

	debug.dumpBinary("secret", secret)
	debug.dumpBinary("context", context)

	if opt.authSecret == nil {
		return
	}

	debug.dumpBinary("hkdf secret", secret)
	debug.dumpBinary("hkdf salt", opt.authSecret)
	debug.dumpBinary("hkdf info", authInfo)

	authSecret := make([]byte, secretLen)
	_, err = hkdf.New(hashAlgorithm, secret, opt.authSecret, authInfo).Read(authSecret)
	if err != nil {
		return
	}
	debug.dumpBinary("authsecret", authSecret)
	return authSecret, context, nil
}

func extractSecret(opt *options) (secret []byte, err error) {
	optKeyLen := len(opt.key)
	if optKeyLen > 0 {
		secret = opt.key
		if optKeyLen != keyLen {
			err = errors.New(fmt.Sprintf("An explicit Key must be %d bytes", keyLen))
		}
		return
	}
	if opt.authSecret == nil {
		return nil, errors.New("no authentication secret for webpush")
	}

	secret = computeSecret(opt.curve, opt.private, opt.dh)
	sp, rp := getKeys(opt)
	authInfo := append(append(webPushInfo, rp...), sp...)

	debug.dumpBinary("hkdf ikm", secret)
	debug.dumpBinary("hkdf salt", opt.authSecret)
	debug.dumpBinary("hkdf info", authInfo)

	newSecret := make([]byte, secretLen)
	_, err = hkdf.New(hashAlgorithm, secret, opt.authSecret, authInfo).Read(newSecret)
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

func newContext(opt *options) []byte {
	var ctx []byte

	if opt.encoding == AESGCM {
		// The context format is:
		// KeyLabel || 0x00 ||
		// length(receiverPublicKey) || receiverPublicKey ||
		// length(senderPublicKey) || senderPublicKey
		// The lengths are 16-bit, Big Endian, unsigned integers so take 2 bytes each.
		keyLabelLen := len(opt.keyLabel)

		sp, rp := getKeys(opt)
		rplen := len(rp)
		rplenbuf := uint16ToBytes(rplen)

		splen := len(sp)
		splenbuf := uint16ToBytes(splen)

		ctx = make([]byte, 0, keyLabelLen+1+2+rplen+2+splen)
		ctx = append(ctx, opt.keyLabel...)
		ctx = append(ctx, 0)
		ctx = append(ctx, rplenbuf...)
		ctx = append(ctx, rp...)
		ctx = append(ctx, splenbuf...)
		ctx = append(ctx, sp...)
	} else {
		ctx = make([]byte, 0)
	}

	return ctx
}

func getKeys(opt *options) (sp []byte, rp []byte) {
	if opt.mode == DECRYPT {
		rp = opt.public
		sp = opt.dh
	} else {
		rp = opt.dh
		sp = opt.public
	}
	return
}
