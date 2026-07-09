/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomKey(t *testing.T) {
	private, err := randomKey()
	assert.Nil(t, err)
	public := private.PublicKey()
	assert.Equal(t, 32, len(private.Bytes()))
	assert.Equal(t, 65, len(public.Bytes()))

	private2, err2 := randomKey()
	assert.Nil(t, err2)
	public2 := private2.PublicKey()
	assert.Equal(t, 32, len(private2.Bytes()))
	assert.Equal(t, 65, len(public2.Bytes()))

	assert.NotEqual(t, private, private2)
	assert.NotEqual(t, public, public2)
}

func TestKeys_Errors(t *testing.T) {
	// Test extractSecret with invalid key length
	opt := &options{
		key: make([]byte, 10), // invalid length (not 16)
	}
	_, err := extractSecret(opt)
	assert.Contains(t, err.Error(), "an explicit Key must be 16 bytes")

	// Test extractSecret with no saved key
	opt = &options{
		keyID:  []byte("missing"),
		keyMap: func(b []byte) []byte { return nil },
	}
	_, err = extractSecret(opt)
	assert.Contains(t, err.Error(), "no saved key")

	// Test extractSecret with no auth secret
	priv, _ := randomKey()
	opt = &options{
		privateKey: priv,
		authSecret: nil,
	}
	_, err = extractSecret(opt)
	assert.Equal(t, ErrNoAuthSecret, err)

	// Test extractDH with invalid receiver public key length
	opt = &options{
		mode:       encrypt,
		privateKey: priv,
		publicKey:  priv.PublicKey(),
		dh:         make([]byte, 70000),
		keyLabel:   []byte("test"),
	}
	// Note: We need to bypass getSecret check or use a valid public key but mock the length check
	// But getSecret calls curve.NewPublicKey which will fail for 70000 bytes.
	// So it will fail early at getSecret.
	_, _, err = extractDH(opt)
	assert.Error(t, err)

	// Test getSecret with invalid public key
	_, err = opt.getSecret([]byte("invalid"))
	assert.Error(t, err)
}

func TestKeys_AdditionalCoverage(t *testing.T) {
	// extractSecretAndContext with keyID and keyMap
	km := func(b []byte) []byte {
		if string(b) == "test" {
			return make([]byte, 16)
		}
		return nil
	}
	opt := &options{
		keyID:  []byte("test"),
		keyMap: km,
	}
	secret, context, err := extractSecretAndContext(opt)
	assert.Nil(t, err)
	assert.NotNil(t, secret)
	assert.Nil(t, context)

	// extractSecretAndContext with invalid key length
	opt = &options{
		key: make([]byte, 10),
	}
	_, _, err = extractSecretAndContext(opt)
	assert.Error(t, err)

	// deriveKeyAndNonce with invalid encoding
	opt = &options{
		encoding: ContentEncoding("invalid"),
	}
	_, _, err = deriveKeyAndNonce(opt)
	assert.Error(t, err)

	// extractSecret (AES128GCM) decrypt mode
	priv, _ := randomKey()
	opt = &options{
		mode:       decrypt,
		encoding:   AES128GCM,
		privateKey: priv,
		publicKey:  priv.PublicKey(),
		keyID:      priv.PublicKey().Bytes(),
		authSecret: make([]byte, 16),
	}
	_, err = extractSecret(opt)
	assert.Nil(t, err)
}

func TestKeys_CreateCipher_Error(t *testing.T) {
	_, err := createCipher(make([]byte, 10)) // invalid key length for AES
	assert.Error(t, err)
}

func TestKeys_ExtractSecretAndContext_Misc(t *testing.T) {
	// AESGCM with keyID only (no keyMap result)
	opt := &options{
		encoding: AESGCM,
		keyID:    []byte("test"),
		keyMap:   func(b []byte) []byte { return nil },
	}
	_, _, err := extractSecretAndContext(opt)
	assert.Equal(t, ErrUnableDetermineKey, err)
}
