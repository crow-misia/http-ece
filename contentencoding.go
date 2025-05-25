/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// ContentEncoding is crypto data encoding
type ContentEncoding string

const (
	AES128GCM ContentEncoding = "aes128gcm"
	AESGCM    ContentEncoding = "aesgcm"
)

// Padding returns crypto data padding size.
func (i ContentEncoding) Padding() uint32 {
	switch i {
	case AES128GCM:
		return 1
	case AESGCM:
		return 2
	default:
		return 0
	}
}

// overhead return record overhead size
func (i ContentEncoding) overhead(gcm cipher.AEAD) uint32 {
	overhead := i.Padding()
	if i == AES128GCM {
		overhead += uint32(gcm.Overhead())
	}
	return overhead
}

func (i ContentEncoding) calculateRecordPadSize(pad, baseRecordSize uint32) uint32 {
	padSize := i.Padding()

	// Pad so that at least one data byte is in a block.
	recordPad := min(baseRecordSize-1, pad)

	if i != AES128GCM {
		recordPad = min((1<<(padSize*8))-1, recordPad)
	}
	if pad > 0 && recordPad == 0 {
		recordPad++ // Deal with perverse case of rs=overhead+1 with padding.
	}
	return recordPad
}

func (i ContentEncoding) calculateCipherBlockEnd(gcm cipher.AEAD, start, contentLen, recordSize uint32) (uint32, error) {
	blockSize := recordSize
	tagSize := uint32(gcm.Overhead())
	if i != AES128GCM {
		blockSize += tagSize
	}
	end := start + blockSize

	if i != AES128GCM && end == contentLen {
		return 0, ErrTruncated
	}

	end = min(end, contentLen)
	if end-start <= tagSize {
		return 0, ErrTruncated
	}
	return end, nil
}

// appendPadding
func (i ContentEncoding) appendPadding(plaintext []byte, pad uint32, last bool) []byte {
	plaintextLen := uint32(len(plaintext))
	result := make([]byte, plaintextLen+i.Padding()+pad)

	switch i {
	case AESGCM:
		binary.BigEndian.PutUint16(result, uint16(pad))
		copy(result[2+pad:], plaintext)
	default:
		copy(result, plaintext)
		if last {
			result[plaintextLen] = 0x02
		} else {
			result[plaintextLen] = 0x01
		}
	}
	return result
}

func (i ContentEncoding) unpad(plaintext []byte, last bool) ([]byte, error) {
	switch i {
	case AES128GCM:
		for i := len(plaintext) - 1; i >= 0; i-- {
			c := plaintext[i]
			switch {
			case c == 0:
				continue
			case last && c != 2:
				return nil, ErrInvalidPaddingLast
			case !last && c != 1:
				return nil, ErrInvalidPaddingNonLast
			default:
				return plaintext[:i], nil
			}
		}

		return nil, ErrAllZeroPlaintext
	default:
		padSize := i.Padding()
		var pad uint32
		switch padSize {
		case 1:
			pad = uint32(plaintext[0])
		case 2:
			pad = uint32(binary.BigEndian.Uint16(plaintext[:2]))
		default:
			return nil, fmt.Errorf("unknown padding size %d", padSize)
		}
		if pad+padSize > uint32(len(plaintext)) {
			return nil, fmt.Errorf("padding exceeds block size: %d", pad)
		}
		return plaintext[pad+padSize:], nil
	}
}

// isLastBlock returns true when last block
func (i ContentEncoding) isLastBlock(pad, contentLen, blockEnd uint32) bool {
	var last bool
	switch i {
	case AES128GCM:
		last = blockEnd >= contentLen
	default:
		// The > here ensures that we write out a padding-only block at the end of a buffer.
		last = blockEnd > contentLen
	}
	return last && pad == 0
}
