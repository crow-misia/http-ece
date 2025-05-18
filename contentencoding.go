/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

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
