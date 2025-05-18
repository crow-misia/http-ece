/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
)

type key []byte
type nonce []byte

func deriveKeyAndNonce(opt *options) (key, nonce, error) {
	var keyInfo, nonceInfo, secret, context []byte
	var err error

	switch opt.encoding {
	case AESGCM:
		// old
		secret, context, err = extractSecretAndContext(opt)
		if err != nil {
			return nil, nil, err
		}
		keyInfo = buildInfo(aesgcmInfo, context)
		nonceInfo = buildInfo(nonceBaseInfo, context)
		break
	case AES128GCM:
		// latest
		secret, err = extractSecret(opt)
		if err != nil {
			return nil, nil, err
		}
		keyInfo = buildInfo(aes128gcmInfo, nil)
		nonceInfo = buildInfo(nonceBaseInfo, nil)
		break
	default:
		return nil, nil, fmt.Errorf("must include a Salt parameter for %s", opt.encoding)
	}

	debug.dumpBinary("info aesgcm", keyInfo)
	debug.dumpBinary("info nonce", nonceInfo)

	debug.dumpBinary("hkdf secret", secret)
	debug.dumpBinary("hkdf salt", opt.salt)

	prk := hkdf.Extract(hashAlgorithm, secret, opt.salt)

	debug.dumpBinary("hkdf prk", prk)
	debug.dumpBinary("hkdf info", keyInfo)

	key := make([]byte, keyLen)
	_, err = hkdf.Expand(hashAlgorithm, prk, keyInfo).Read(key)
	if err != nil {
		return nil, nil, err
	}

	debug.dumpBinary("key", key)
	debug.dumpBinary("hkdf prk", prk)
	debug.dumpBinary("hkdf info", nonceInfo)

	nonce := make([]byte, nonceLen)
	if _, err = hkdf.Expand(hashAlgorithm, prk, nonceInfo).Read(nonce); err != nil {
		return nil, nil, err
	}
	debug.dumpBinary("base nonce", nonce)
	return key, nonce, err
}

func createCipher(key key) (cipher.AEAD, error) {
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
			return nil, nil, fmt.Errorf("an explicit Key must be %d bytes", keyLen)
		}
		context = nil
	} else if opt.private != nil {
		if secret, err = getSecret(opt); err != nil {
			return nil, nil, err
		}
		context = newContext(opt)
	} else if opt.keyID != nil {
		secret = opt.keyMap(opt.keyID)
		context = nil
	}

	if secret == nil {
		return nil, nil, errors.New("unable to determine key")
	}

	debug.dumpBinary("secret", secret)
	debug.dumpBinary("context", context)

	if opt.authSecret == nil {
		return secret, context, nil
	}

	debug.dumpBinary("hkdf secret", secret)
	debug.dumpBinary("hkdf salt", opt.authSecret)
	debug.dumpBinary("hkdf info", authInfo)

	authSecret := make([]byte, secretLen)
	_, err = io.ReadFull(hkdf.New(hashAlgorithm, secret, opt.authSecret, authInfo), authSecret)
	if err != nil {
		return nil, nil, err
	}
	debug.dumpBinary("authsecret", authSecret)
	return authSecret, context, nil
}

func extractSecret(opt *options) ([]byte, error) {
	optKeyLen := len(opt.key)
	if optKeyLen > 0 {
		if optKeyLen != keyLen {
			return nil, fmt.Errorf("an explicit Key must be %d bytes", keyLen)
		}
		return opt.key, nil
	}
	if opt.authSecret == nil {
		return nil, errors.New("no authentication secret for webpush")
	}

	var secret []byte
	var err error
	if secret, err = getSecret(opt); err != nil {
		return nil, err
	}
	sp, rp := getKeys(opt)
	authInfo := append(append(webPushInfo, rp...), sp...)

	debug.dumpBinary("hkdf ikm", secret)
	debug.dumpBinary("hkdf salt", opt.authSecret)
	debug.dumpBinary("hkdf info", authInfo)

	newSecret := make([]byte, secretLen)
	_, err = hkdf.New(hashAlgorithm, secret, opt.authSecret, authInfo).Read(newSecret)
	if err != nil {
		return nil, err
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
	if opt.encoding != AESGCM {
		return nil
	}

	// The context format is:
	// KeyLabel || 0x00 ||
	// length(receiverPublicKey) || receiverPublicKey ||
	// length(senderPublicKey) || senderPublicKey
	// The lengths are 16-bit, Big Endian, unsigned integers so take 2 bytes each.
	keyLabelLen := len(opt.keyLabel)

	sp, rp := getKeys(opt)
	rplen := len(rp)
	rplenbuf := uint16ToBytes(uint16(rplen))

	splen := len(sp)
	splenbuf := uint16ToBytes(uint16(splen))

	ctx := make([]byte, keyLabelLen+1+2+rplen+2+splen)
	copy(ctx, opt.keyLabel)
	ctx[keyLabelLen] = 0x00
	copy(ctx[keyLabelLen+1:], rplenbuf)
	copy(ctx[keyLabelLen+3:], rp)
	copy(ctx[keyLabelLen+3+rplen:], splenbuf)
	copy(ctx[keyLabelLen+3+rplen+2:], sp)
	return ctx
}

func randomKey() (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand.Reader)
}

func getKeys(opt *options) (sp, rp []byte) {
	if opt.mode == decrypt {
		return opt.dh, opt.public
	}
	return opt.public, opt.dh
}

func getSecret(opt *options) (secret []byte, err error) {
	var dh *ecdh.PublicKey
	if dh, err = curve.NewPublicKey(opt.dh); err != nil {
		return nil, err
	}
	return opt.privateKey.ECDH(dh)
}
