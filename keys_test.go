package http_ece

import (
	"crypto/elliptic"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRandomKey(t *testing.T) {
	private, public, err := randomKey(elliptic.P256())
	assert.Nil(t, err)
	assert.Equal(t, 32, len(private))
	assert.Equal(t, 65, len(public))

	private2, public2, err2 := randomKey(elliptic.P256())
	assert.Nil(t, err2)
	assert.Equal(t, 32, len(private2))
	assert.Equal(t, 65, len(public2))

	assert.NotEqual(t, private, private2)
	assert.NotEqual(t, public, public2)
}
