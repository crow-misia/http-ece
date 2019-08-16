/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package http_ece

import (
	"crypto/elliptic"
)

type options struct {
	mode       Mode                // Encrypt / Decrypt Mode
	curve      elliptic.Curve      // Curve Algorithm
	encoding   ContentEncoding     // Content Encoding
	rs         int                 // Record Size
	salt       []byte              // Encryption salt
	key        []byte              // Encryption key data
	authSecret []byte              // Auth Secret
	private    []byte              // DH Private key
	public     []byte              // DH Public key
	dh         []byte              // Remote Diffie Hellman sequence
	keyId      []byte              // key Identifier
	keyLabel   []byte              // Key Label
	keyMap     func([]byte) []byte // Key Mapping Function
}

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
		opts.rs = int(v)
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

type Option func(*options)
