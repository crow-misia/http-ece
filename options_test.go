/*
 * Copyright (c) 2026 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptions_Coverage(t *testing.T) {
	// Test WithPadSize error
	opt := WithPadSize(-1)
	err := opt(&options{})
	assert.Error(t, err)

	// Test WithRecordSize error
	opt = WithRecordSize(-1)
	err = opt(&options{})
	assert.Error(t, err)

	opt = WithRecordSize(recordSizeMax + 1)
	err = opt(&options{})
	assert.Error(t, err)

	// Test WithKey
	opt = WithKey([]byte("key"))
	o := &options{}
	err = opt(o)
	assert.Nil(t, err)
	assert.Equal(t, []byte("key"), o.key)

	// Test WithKeyID
	opt = WithKeyID(make([]byte, 300))
	err = opt(o)
	assert.Equal(t, ErrKeyIDTooLong, err)

	opt = WithKeyID([]byte("id"))
	err = opt(o)
	assert.Nil(t, err)
	assert.Equal(t, []byte("id"), o.keyID)

	// Test WithKeyLabel
	opt = WithKeyLabel([]byte("label"))
	err = opt(o)
	assert.Nil(t, err)
	assert.Equal(t, []byte("label"), o.keyLabel)

	// Test WithKeyMap
	km := func(b []byte) []byte { return b }
	opt = WithKeyMap(km)
	err = opt(o)
	assert.Nil(t, err)
	// Function comparison is not possible, but we can call it
	assert.Equal(t, []byte("test"), o.keyMap([]byte("test")))
}

func TestOptions_ParseOptions_Error(t *testing.T) {
	// This is hard to trigger as randomKey() usually succeeds,
	// but we can try with a custom curve if we could inject it.
	// For now, let's at least cover parseOptions error.
	_, err := parseOptions(encrypt, []Option{func(o *options) error { return fmt.Errorf("error") }})
	assert.Error(t, err)
}
