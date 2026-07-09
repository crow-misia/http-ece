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
	assert.Equal(t, 2, AESGCM.Padding())
	assert.Equal(t, 1, AES128GCM.Padding())
	assert.Equal(t, 0, ContentEncoding("unknown").Padding())
}

func TestContentEncoding_Unpad_Errors(t *testing.T) {
	// AES128GCM error cases
	_, err := AES128GCM.unpad([]byte{0, 0, 0}, true)
	assert.Equal(t, ErrAllZeroPlaintext, err)

	_, err = AES128GCM.unpad([]byte{0, 0, 3}, true)
	assert.Equal(t, ErrInvalidPaddingLast, err)

	_, err = AES128GCM.unpad([]byte{0, 0, 3}, false)
	assert.Equal(t, ErrInvalidPaddingNonLast, err)

	// Other (AESGCM) error cases
	_, err = ContentEncoding("unknown").unpad([]byte{0, 0, 0}, true)
	assert.Contains(t, err.Error(), "unknown padding size 0")

	_, err = AESGCM.unpad([]byte{0, 10}, true)
	assert.Contains(t, err.Error(), "padding exceeds block size: 12")
}

func TestContentEncoding_AppendPadding_Error(t *testing.T) {
	_, err := AESGCM.appendPadding([]byte("test"), -1, true)
	assert.Error(t, err)

	_, err = AESGCM.appendPadding([]byte("test"), 70000, true)
	assert.Error(t, err)
}

func TestContentEncoding_IsLastBlock(t *testing.T) {
	assert.True(t, AES128GCM.isLastBlock(0, 10, 10))
	assert.False(t, AES128GCM.isLastBlock(1, 10, 10))
	assert.True(t, AESGCM.isLastBlock(0, 10, 11))
	assert.False(t, AESGCM.isLastBlock(0, 10, 10))
}

func TestContentEncoding_Padding_Misc(t *testing.T) {
	// rs=overhead+1 case in calculateRecordPadSize
	gcm, _ := createCipher(make([]byte, 16))
	_ = AES128GCM.overhead(gcm)
	// baseRecordSize = 1
	pad := AES128GCM.calculateRecordPadSize(10, 1)
	assert.Equal(t, 1, pad)
}

func TestContentEncoding_CalculateCipherBlockEnd_Truncated(t *testing.T) {
	gcm, _ := createCipher(make([]byte, 16))
	// end-start <= tagSize case
	_, err := AES128GCM.calculateCipherBlockEnd(gcm, 0, 10, 4096)
	assert.Equal(t, ErrTruncated, err)
}
