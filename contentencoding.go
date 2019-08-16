/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package http_ece

//go:generate stringer -type=ContentEncoding
type ContentEncoding int

const (
	_ ContentEncoding = iota
	AES128GCM
	AESGCM
)

func (i ContentEncoding) Padding() int {
	switch i {
	case AES128GCM:
		return 1
	case AESGCM:
		return 2
	}
	return 0
}
