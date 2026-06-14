/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/ecdh"
	"fmt"
)

type KeyMappingFn func([]byte) []byte

type options struct {
	mode       mode             // Encrypt / Decrypt Mode
	encoding   ContentEncoding  // Content Encoding
	recordSize uint32           // Record Size
	salt       []byte           // Encryption salt
	key        []byte           // Encryption key data
	padSize    int              // Record padding size
	authSecret []byte           // Auth Secret
	keyID      []byte           // key Identifier
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

func WithEncoding(value ContentEncoding) Option {
	return func(opts *options) error {
		opts.encoding = value
		return nil
	}
}

func WithSalt(value []byte) Option {
	return func(opts *options) error {
		opts.salt = value
		return nil
	}
}

func WithPadSize(value int) Option {
	return func(opts *options) error {
		if value < 0 {
			return fmt.Errorf("invalid padding size %d: must be non-negative", value)
		}
		opts.padSize = value
		return nil
	}
}

func WithPrivate(value []byte) Option {
	return func(opts *options) (err error) {
		opts.privateKey, err = curve.NewPrivateKey(value)
		return err
	}
}

func WithDh(value []byte) Option {
	return func(opts *options) error {
		opts.dh = value
		return nil
	}
}

func WithAuthSecret(value []byte) Option {
	return func(opts *options) error {
		opts.authSecret = value
		return nil
	}
}

func WithRecordSize(value int) Option {
	return func(opts *options) error {
		if value < 0 || value > recordSizeMax {
			return fmt.Errorf("invalid record size %d: must be between 0 and %d", value, recordSizeMax)
		}
		opts.recordSize = uint32(value)
		return nil
	}
}

func WithKey(value []byte) Option {
	return func(opts *options) error {
		opts.key = value
		return nil
	}
}

func WithKeyID(value []byte) Option {
	return func(opts *options) error {
		if len(value) > keyIDLenMax {
			return ErrKeyIDTooLong
		}
		opts.keyID = value
		return nil
	}
}

func WithKeyLabel(value []byte) Option {
	return func(opts *options) error {
		opts.keyLabel = value
		return nil
	}
}

func WithKeyMap(value KeyMappingFn) Option {
	return func(opts *options) error {
		opts.keyMap = value
		return nil
	}
}
