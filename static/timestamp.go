package main

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

var base32Encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

func main() {
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
	fmt.Println(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]))
}
