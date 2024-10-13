package notebrew

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ID is a 16-byte UUID that is sortable by a timestamp component. The first 5
// bytes of the ID are the timestamp component and the remaining 11 bytes are
// completely random. Unlike UUIDv7, there is no version byte and there are no
// monotonic guarantees, which makes generating a spec-compliant ID much
// simpler.
//
// The timestamp component is 5 bytes so that it can be perfectly encoded by an
// 8-character Base32 string. While this feature is not used by IDs because
// they are always displayed in canonical UUID form
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx for maxmimum compatibility, these 5
// byte timestamps appear in other places in notebrew which do exploit the fact
// that they can be perfectly encoded by an 8-character Base32 string so it
// just seems like a good idea to ensure all timestamp prefixes occupy 5 bytes
// for consistency.
type ID [16]byte

// NewID creates a new ID.
func NewID() ID {
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
	var id ID
	copy(id[:5], timestamp[len(timestamp)-5:])
	_, err := rand.Read(id[5:])
	if err != nil {
		panic(err)
	}
	return id
}

// ParseID parses a UUID string of the format
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx into an ID.
func ParseID(s string) (ID, error) {
	if len(s) == 0 {
		return ID{}, nil
	}
	if len(s) != 36 {
		return ID{}, errors.New("invalid ID")
	}
	var id ID
	for i, x := range [16]int{
		0, 2, 4, 6,
		9, 11,
		14, 16,
		19, 21,
		24, 26, 28, 30, 32, 34,
	} {
		v, ok := xtob(s[x], s[x+1])
		if !ok {
			return ID{}, errors.New("invalid ID")
		}
		id[i] = v
	}
	return id, nil
}

// IsZero reports if an ID is all zeroes, which is used to represent the null
// state.
func (id ID) IsZero() bool {
	return id == ID{}
}

// String prints the ID in UUID format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func (id ID) String() string {
	if id.IsZero() {
		return ""
	}
	var b [32 + 4]byte // 32 ASCII + 4 dashes
	hex.Encode(b[:], id[:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:], id[10:])
	return string(b[:])
}

// MarshalJSON converts an ID to a JSON string in the format
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func (id ID) MarshalJSON() ([]byte, error) {
	if id.IsZero() {
		return []byte(`""`), nil
	}
	var array [32 + 4 + 2]byte // 32 ASCII + 4 dashes + 2 quotes
	array[0], array[len(array)-1] = '"', '"'
	b := array[1 : len(array)-1]
	hex.Encode(b[:], id[:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:], id[10:])
	return array[:], nil
}

// UnmarshalJSON converts a JSON string in the format
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx into an ID. If the JSON value is null,
// the existing ID's value is untouched.
func (id *ID) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	*id = ID{}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("cannot unmarshal non-string %s into an ID", string(data))
	}
	b := data[1 : len(data)-1]
	if len(b) == 0 {
		return nil
	}
	if len(b) != 36 {
		return errors.New("invalid ID")
	}
	for i, x := range [16]int{
		0, 2, 4, 6,
		9, 11,
		14, 16,
		19, 21,
		24, 26, 28, 30, 32, 34,
	} {
		v, ok := xtob(b[x], b[x+1])
		if !ok {
			return errors.New("invalid ID")
		}
		(*id)[i] = v
	}
	return nil
}

// Copyright (c) 2009,2014 Google Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// https://github.com/google/uuid

// xvalues returns the value of a byte as a hexadecimal digit or 255.
var xvalues = [256]byte{
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
}

// xtob converts hex characters x1 and x2 into a byte.
func xtob(x1, x2 byte) (byte, bool) {
	b1 := xvalues[x1]
	b2 := xvalues[x2]
	return (b1 << 4) | b2, b1 != 255 && b2 != 255
}
