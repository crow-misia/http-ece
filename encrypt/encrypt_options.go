package encrypt

import (
	"crypto/elliptic"
	"github.com/crow-misia/http-ece"
	. "github.com/crow-misia/http-ece/internal"
)

type options struct {
	curve       elliptic.Curve           // Curve Algorithm
	encoding    http_ece.ContentEncoding // Content Encoding
	rs          int                      // Record Size
	salt        []byte                   // Encryption salt
	key         []byte                   // Encryption key data
	authSecret  []byte                   // Auth Secret
	private     []byte                   // Private key
	public      []byte                   // Public key
	peersPublic []byte                   // Peers Public key
	keyId       []byte                   // key Identifier
	keyLabel    []byte                   // Key Label
}

func (o *options) toKeyConfig() *KeyConfig {
	return &KeyConfig{
		Curve:          o.curve,
		Encoding:       o.encoding,
		Key:            o.key,
		Salt:           o.salt,
		AuthSecret:     o.authSecret,
		Dh:             o.peersPublic,
		SenderPublic:   o.public,
		ReceiverPublic: o.peersPublic,
		Private:        o.private,
		KeyLabel:       o.keyLabel,
	}
}

func WithEncoding(v http_ece.ContentEncoding) Option {
	return func(opts *options) {
		opts.encoding = v
	}
}

func WithSalt(v []byte) Option {
	return func(opts *options) {
		opts.salt = v
	}
}

func WithPrivate(v []byte) Option {
	return func(opts *options) {
		opts.private = v
	}
}

func WithPeersPublic(v []byte) Option {
	return func(opts *options) {
		opts.peersPublic = v
	}
}

func WithAuthSecret(v []byte) Option {
	return func(opts *options) {
		opts.authSecret = v
	}
}

func WithKeyLabel(v []byte) Option {
	return func(opts *options) {
		opts.keyLabel = v
	}
}

type Option func(*options)
