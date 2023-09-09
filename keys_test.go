/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRandomKey(t *testing.T) {
	private, err := randomKey(ecdh.P256())
	assert.Nil(t, err)
	public := private.PublicKey()
	assert.Equal(t, 32, len(private.Bytes()))
	assert.Equal(t, 65, len(public.Bytes()))

	private2, err2 := randomKey(ecdh.P256())
	assert.Nil(t, err2)
	public2 := private2.PublicKey()
	assert.Equal(t, 32, len(private2.Bytes()))
	assert.Equal(t, 65, len(public2.Bytes()))

	assert.NotEqual(t, private, private2)
	assert.NotEqual(t, public, public2)
}
