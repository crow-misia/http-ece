package http_ece

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUint16ToBytes(t *testing.T) {
	assert.Equal(t, []byte{0x00, 0x01}, uint16ToBytes(1))
	assert.Equal(t, []byte{0x00, 0x11}, uint16ToBytes(17))
	assert.Equal(t, []byte{0x01, 0x01}, uint16ToBytes(257))
}

func d(text string) []byte {
	b, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return b
}
