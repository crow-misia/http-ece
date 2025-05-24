/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/ecdh"
)

type KeyMappingFn func([]byte) []byte

type options struct {
	mode       mode             // Encrypt / Decrypt Mode
	curve      ecdh.Curve       // Curve Algorithm
	encoding   ContentEncoding  // Content Encoding
	recordSize uint32           // Record Size
	salt       []byte           // Encryption salt
	key        []byte           // Encryption key data
	authSecret []byte           // Auth Secret
	keyId      []byte           // key Identifier
	keyLabel   []byte           // Key Label
	keyMap     KeyMappingFn     // Key Mapping Function
	privateKey *ecdh.PrivateKey // DH Private key
	publicKey  *ecdh.PublicKey  // DH Public key
	dh         []byte           // Remote Diffie Hellman sequence
}

func (o *options) initialize() error {
	// Create or Set private key.
	var privateKey *ecdh.PrivateKey
	var err error
	if o.privateKey == nil {
		if privateKey, err = randomKey(); err != nil {
			return err
		}
		o.privateKey = privateKey
	}
	o.publicKey = o.privateKey.PublicKey()
	return nil
}

type Option func(*options) error

func WithEncoding(v ContentEncoding) Option {
	return func(opts *options) error {
		opts.encoding = v
		return nil
	}
}

func WithSalt(v []byte) Option {
	return func(opts *options) error {
		opts.salt = v
		return nil
	}
}

func WithPrivate(v []byte) Option {
	return func(opts *options) (err error) {
		opts.privateKey, err = curve.NewPrivateKey(v)
		return err
	}
}

func WithDh(v []byte) Option {
	return func(opts *options) error {
		opts.dh = v
		return nil
	}
}

func WithAuthSecret(v []byte) Option {
	return func(opts *options) error {
		opts.authSecret = v
		return nil
	}
}

func WithRecordSize(v uint32) Option {
	return func(opts *options) error {
		opts.recordSize = v
		return nil
	}
}

func WithKey(v []byte) Option {
	return func(opts *options) error {
		opts.key = v
		return nil
	}
}

func WithKeyId(v []byte) Option {
	return func(opts *options) error {
		if len(v) > keyIdLenMax {
			return ErrKeyIdTooLong
		}
		opts.keyId = v
		return nil
	}
}

func WithKeyLabel(v []byte) Option {
	return func(opts *options) error {
		opts.keyLabel = v
		return nil
	}
}

func WithKeyMap(v KeyMappingFn) Option {
	return func(opts *options) error {
		opts.keyMap = v
		return nil
	}
}
