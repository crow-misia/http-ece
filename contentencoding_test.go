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

func TestContentEncoding_Padding(t *testing.T) {
	assert.Equal(t, uint32(2), AESGCM.Padding())
	assert.Equal(t, uint32(1), AES128GCM.Padding())
}
