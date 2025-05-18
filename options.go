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

type options struct {
	mode       mode                // Encrypt / Decrypt Mode
	curve      ecdh.Curve          // Curve Algorithm
	encoding   ContentEncoding     // Content Encoding
	recordSize uint32              // Record Size
	salt       []byte              // Encryption salt
	key        []byte              // Encryption key data
	authSecret []byte              // Auth Secret
	private    []byte              // DH Private key
	public     []byte              // DH Public key
	dh         []byte              // Remote Diffie Hellman sequence
	keyID      []byte              // key Identifier
	keyLabel   []byte              // Key Label
	keyMap     func([]byte) []byte // Key Mapping Function
	privateKey *ecdh.PrivateKey    // DH Private key
}

func (o *options) initialize() error {
	// Create or Set private key.
	var privateKey *ecdh.PrivateKey
	var err error
	if o.private == nil {
		if privateKey, err = randomKey(); err != nil {
			return err
		}
		o.privateKey = privateKey
		o.private = privateKey.Bytes()
	} else {
		if privateKey, err = curve.NewPrivateKey(o.private); err != nil {
			return err
		}
		o.privateKey = privateKey
	}
	o.public = privateKey.PublicKey().Bytes()
	return nil
}

type Option func(*options)

func WithEncoding(v ContentEncoding) Option {
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

func WithDh(v []byte) Option {
	return func(opts *options) {
		opts.dh = v
	}
}

func WithAuthSecret(v []byte) Option {
	return func(opts *options) {
		opts.authSecret = v
	}
}

func WithRecordSize(v uint32) Option {
	return func(opts *options) {
		opts.recordSize = v
	}
}

func WithKeyLabel(v []byte) Option {
	return func(opts *options) {
		opts.keyLabel = v
	}
}

func WithKeyMap(v func([]byte) []byte) Option {
	return func(opts *options) {
		opts.keyMap = v
	}
}
