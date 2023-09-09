/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package httpece

//go:generate stringer -type=ContentEncoding

// ContentEncoding is crypto data encoding
type ContentEncoding int

const (
	_ ContentEncoding = iota
	AES128GCM
	AESGCM
)

// Padding returns crypto data padding size.
func (i ContentEncoding) Padding() int {
	switch i {
	case AES128GCM:
		return 1
	case AESGCM:
		return 2
	}
	return 0
}
