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
	_, err = io.ReadFull(hkdf.Expand(hashAlgorithm, prk, keyInfo), key)
	if err != nil {
		return nil, nil, err
	}

	debug.dumpBinary("key", key)
	debug.dumpBinary("hkdf prk", prk)
	debug.dumpBinary("hkdf info", nonceInfo)

	nonce := make([]byte, nonceLen)
	if _, err = io.ReadFull(hkdf.Expand(hashAlgorithm, prk, nonceInfo), nonce); err != nil {
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
	} else if opt.dh != nil {
		if secret, context, err = extractDH(opt); err != nil {
			return nil, nil, err
		}
	} else if opt.keyID != nil {
		secret = opt.keyMap(opt.keyID)
		context = nil
	}

	if secret == nil {
		return nil, nil, ErrUnableDetermineKey
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
	if opt.privateKey == nil {
		key := opt.keyMap(opt.keyID)
		if key == nil {
			return nil, fmt.Errorf("no saved key (keyID: \"%s\")", opt.keyID)
		}
		return key, nil
	}
	if opt.authSecret == nil {
		return nil, ErrNoAuthSecret
	}
	debug.dumpBinary("authsecret", opt.authSecret)

	var remotePublicKey, senderPublicKey, receiverPublicKey []byte
	if opt.mode == encrypt {
		senderPublicKey = opt.publicKey.Bytes()
		receiverPublicKey = opt.dh
		remotePublicKey = opt.dh
	} else {
		remotePublicKey = opt.keyID
		senderPublicKey = opt.keyID
		receiverPublicKey = opt.publicKey.Bytes()
	}

	debug.dumpBinary("remote public key", remotePublicKey)
	debug.dumpBinary("sender public key", senderPublicKey)
	debug.dumpBinary("receiver public key", receiverPublicKey)

	authInfo := append(append(webPushInfo, receiverPublicKey...), senderPublicKey...)

	secret, err := opt.getSecret(remotePublicKey)
	if err != nil {
		return nil, err
	}
	debug.dumpBinary("hkdf ikm", secret)
	debug.dumpBinary("hkdf info", authInfo)

	newSecret := make([]byte, secretLen)
	_, err = io.ReadFull(hkdf.New(hashAlgorithm, secret, opt.authSecret, authInfo), newSecret)
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

func extractDH(opt *options) (secret []byte, context []byte, err error) {
	secret, err = opt.getSecret(opt.dh)
	if err != nil {
		return nil, nil, err
	}

	key := opt.privateKey
	var senderPublicKey, receiverPublicKey []byte
	if opt.mode == encrypt {
		senderPublicKey = key.PublicKey().Bytes()
		receiverPublicKey = opt.dh
	} else {
		senderPublicKey = opt.dh
		receiverPublicKey = key.PublicKey().Bytes()
	}

	// The context format is:
	// KeyLabel || 0x00 ||
	// length(receiverPublicKey) || receiverPublicKey ||
	// length(senderPublicKey) || senderPublicKey
	// The lengths are 16-bit, Big Endian, unsigned integers so take 2 bytes each.
	keyLabelLen := len(opt.keyLabel)

	rplen := len(receiverPublicKey)
	rplenbuf := uint16ToBytes(uint16(rplen))

	splen := len(senderPublicKey)
	splenbuf := uint16ToBytes(uint16(splen))

	ctx := make([]byte, keyLabelLen+1+2+rplen+2+splen)
	copy(ctx, opt.keyLabel)
	ctx[keyLabelLen] = 0x00
	copy(ctx[keyLabelLen+1:], rplenbuf)
	copy(ctx[keyLabelLen+3:], receiverPublicKey)
	copy(ctx[keyLabelLen+3+rplen:], splenbuf)
	copy(ctx[keyLabelLen+3+rplen+2:], senderPublicKey)

	return secret, ctx, nil
}

func randomKey() (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand.Reader)
}

func (o *options) getSecret(publicKey []byte) (secret []byte, err error) {
	var dh *ecdh.PublicKey
	if dh, err = curve.NewPublicKey(publicKey); err != nil {
		return nil, err
	}
	return o.privateKey.ECDH(dh)
}
