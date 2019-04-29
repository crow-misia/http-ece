package internal

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUint16ToBytes(t *testing.T) {
	assert.Equal(t, []byte{0x00, 0x01}, Uint16ToBytes(1))
	assert.Equal(t, []byte{0x00, 0x11}, Uint16ToBytes(17))
	assert.Equal(t, []byte{0x01, 0x01}, Uint16ToBytes(257))
}
