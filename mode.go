/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of http-ece, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package http_ece

type Mode int

const (
	_ Mode = iota
	DECRYPT
	ENCRYPT
)
