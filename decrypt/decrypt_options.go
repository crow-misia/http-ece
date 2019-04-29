package decrypt

import (
	"crypto/elliptic"
	"github.com/crow-misia/http-ece"
	. "github.com/crow-misia/http-ece/internal"
)

type options struct {
	curve      elliptic.Curve           // Curve Algorithm
	encoding   http_ece.ContentEncoding // Content Encoding
	rs         int                      // Record Size
	salt       []byte                   // Encryption salt
	key        []byte                   // Encryption key data
	authSecret []byte                   // Auth Secret
	dh         []byte                   // Sender Public key
	private    []byte                   // Peers Private key
	public     []byte                   // Peers Public key
	keyId      []byte                   // key Identifier
	keyLabel   []byte                   // Key Label
	keyMap     func([]byte) []byte      // Key Mapping Function
}

func (o *options) toKeyConfig() *KeyConfig {
	return &KeyConfig{
		Curve:          o.curve,
		Encoding:       o.encoding,
		Key:            o.key,
		Salt:           o.salt,
		AuthSecret:     o.authSecret,
		Dh:             o.dh,
		SenderPublic:   o.dh,
		ReceiverPublic: o.public,
		Private:        o.private,
		KeyLabel:       o.keyLabel,
		KeyId:          o.keyId,
		KeyMap:         o.keyMap,
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

func WithDh(v []byte) Option {
	return func(opts *options) {
		opts.dh = v
	}
}

func WithPeersPrivate(v []byte) Option {
	return func(opts *options) {
		opts.private = v
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

func WIthKeyMap(v func([]byte) []byte) Option {
	return func(opts *options) {
		opts.keyMap = v
	}
}

type Option func(*options)
