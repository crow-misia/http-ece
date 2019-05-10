package http_ece

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"log"
)

var debug = debugT(false)

type debugT bool

func (d debugT) dumpBinary(base string, data []byte) {
	if d {
		log.Printf("%12s [%4d]: %s\n", base, len(data), base64.StdEncoding.EncodeToString(data))
	}
}

func parseOptions(mode mode, opts []Option) *options {
	opt := &options{
		mode:     mode,
		curve:    elliptic.P256(),
		encoding: AES128GCM,
		rs:       sizeRecordDefault,
		keyLabel: curveAlgorithm,
	}
	for _, o := range opts {
		o(opt)
	}

	return opt
}

func uint16ToBytes(i int) []byte {
	x := make([]byte, 2)
	binary.BigEndian.PutUint16(x, uint16(i))
	return x
}

func uint32ToBytes(i int) []byte {
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(i))
	return x
}

func generateNonce(baseNonce []byte, counter int) []byte {
	x := make([]byte, nonceLen)
	binary.BigEndian.PutUint32(x[8:], uint32(counter))
	xor12(x, baseNonce, x)
	return x
}

func xor12(dst []byte, a []byte, b []byte) {
	_ = dst[11]
	_ = a[11]
	_ = b[11]

	dst[0] = a[0] ^ b[0]
	dst[1] = a[1] ^ b[1]
	dst[2] = a[2] ^ b[2]
	dst[3] = a[3] ^ b[3]
	dst[4] = a[4] ^ b[4]
	dst[5] = a[5] ^ b[5]
	dst[6] = a[6] ^ b[6]
	dst[7] = a[7] ^ b[7]
	dst[8] = a[8] ^ b[8]
	dst[9] = a[9] ^ b[9]
	dst[10] = a[10] ^ b[10]
	dst[11] = a[11] ^ b[11]
}

func resultsJoin(s [][]byte) []byte {
	if len(s) == 1 {
		return s[0]
	}

	n := 0
	for _, v := range s {
		n += len(v)
	}

	b := make([]byte, n)
	o := 0
	for _, v := range s {
		o += copy(b[o:], v)
	}
	return b
}

func randomSalt() ([]byte, error) {
	salt := make([]byte, keyLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
