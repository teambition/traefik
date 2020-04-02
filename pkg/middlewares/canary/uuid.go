package canary

import (
	"encoding/hex"
	"math/rand"
)

// uuid version 4
type uuidv4 [16]byte

// String https://github.com/satori/go.uuid/blob/master/uuid.go
func (u uuidv4) String() string {
	buf := make([]byte, 36)

	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])

	return string(buf)
}

func generatorUUID() string {
	id := uuidv4{}
	if _, err := rand.Read(id[:]); err != nil {
		return ""
	}

	// https://tools.ietf.org/html/rfc4122#section-4.1.3
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80

	return id.String()
}
