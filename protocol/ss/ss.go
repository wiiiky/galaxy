/*
 * Copyright (C) 2018 Wiky Lyu
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.";
 */

package ss

import (
	"bytes"
	"crypto/md5"
	"galaxy/protocol/socks"
)

func CreateKey(password string, klen int) []byte {
	if klen <= 0 {
		return nil
	}
	var last []byte = nil
	total := 0
	buf := bytes.Buffer{}
	for total < klen {
		data := append(last, []byte(password)...)
		checksum := md5.Sum(data)
		last = checksum[:]
		total += len(last)
		buf.Write(last)
	}
	return buf.Bytes()[:klen]
}

func NewAddressRequest(atype byte, addr string, port uint16) *AddressRequest {
	return &AddressRequest{
		ATYP: atype,
		ADDR: addr,
		PORT: port,
	}
}

func ParseAddressRequest(buf []byte) (*AddressRequest, error) {
	if len(buf) < 7 {
		return nil, ErrInvalidMessage
	}

	atype, addr, port, buf, err := socks.ParseAddrPort(buf)
	if err != nil {
		return nil, err
	}
	req := NewAddressRequest(atype, addr, port)
	req.BUF = buf
	return req, nil
}

func (req *AddressRequest) Build() []byte {
	return socks.BuildAddrPort(req.ATYP, req.ADDR, req.PORT)
}
