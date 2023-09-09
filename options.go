/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/ecdh"
	"crypto/rand"
)

type options struct {
	mode       mode                // Encrypt / Decrypt Mode
	curve      ecdh.Curve          // Curve Algorithm
	encoding   ContentEncoding     // Content Encoding
	rs         int                 // Record Size
	salt       []byte              // Encryption salt
	key        []byte              // Encryption key data
	authSecret []byte              // Auth Secret
	private    *ecdh.PrivateKey    // DH Private key
	dh         *ecdh.PublicKey     // Remote Diffie Hellman sequence
	keyID      []byte              // key Identifier
	keyLabel   []byte              // Key Label
	keyMap     func([]byte) []byte // Key Mapping Function
}

type Option func() (func(*options), error)

func success(opt func(*options)) Option {
	return func() (func(*options), error) {
		return opt, nil
	}
}

func failure(err error) Option {
	return func() (func(*options), error) {
		return nil, err
	}
}

func WithEncoding(v ContentEncoding) Option {
	return success(func(opts *options) {
		opts.encoding = v
	})
}

func WithSalt(v []byte) Option {
	return success(func(opts *options) {
		opts.salt = v
	})
}

func WithRandomPrivate(curve ecdh.Curve) Option {
	private, err := curve.GenerateKey(rand.Reader)
	if err == nil {
		return success(func(opts *options) {
			opts.private = private
		})
	}
	return failure(err)
}

func WithPrivate(curve ecdh.Curve, v []byte) Option {
	private, err := curve.NewPrivateKey(v)
	if err == nil {
		return success(func(opts *options) {
			opts.private = private
		})
	}
	return failure(err)
}

func WithDh(curve ecdh.Curve, v []byte) Option {
	public, err := curve.NewPublicKey(v)
	if err == nil {
		return success(func(opts *options) {
			opts.dh = public
		})
	}
	return failure(err)
}

func WithAuthSecret(v []byte) Option {
	return success(func(opts *options) {
		opts.authSecret = v
	})
}

func WithRecordSize(v uint32) Option {
	return success(func(opts *options) {
		opts.rs = int(v)
	})
}

func WithKeyLabel(v []byte) Option {
	return success(func(opts *options) {
		opts.keyLabel = v
	})
}

func WithKeyMap(v func([]byte) []byte) Option {
	return success(func(opts *options) {
		opts.keyMap = v
	})
}
