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

package socks

import (
	"bytes"
	"encoding/binary"
	"net"
)

func ParseMethodSelectionRequest(buf []byte) (*MethodSelectionRequest, error) {
	if len(buf) < 3 {
		return nil, ErrInvalidMessage
	}
	ver := buf[0]
	nmethods := buf[1]
	if nmethods == 0 || int(nmethods+2) != len(buf) {
		return nil, ErrInvalidMessage
	}
	methods := make([]byte, nmethods)
	for i, v := range buf[2:] {
		methods[i] = v
	}
	return NewMethodSelectionRequest(ver, methods...), nil
}

func NewMethodSelectionRequest(ver byte, methods ...byte) *MethodSelectionRequest {
	return &MethodSelectionRequest{
		VER:      ver,
		NMETHODS: byte(len(methods)),
		METHODS:  methods,
	}
}

func (req *MethodSelectionRequest) Build() []byte {
	buf := make([]byte, 2+len(req.METHODS))
	buf[0] = req.VER
	buf[1] = req.NMETHODS
	for i, v := range req.METHODS {
		buf[2+i] = v
	}
	return buf
}

func ParseMethodSelectionReply(buf []byte) (*MethodSelectionReply, error) {
	if len(buf) != 2 {
		return nil, ErrInvalidMessage
	}
	return NewMethodSelectionReply(buf[0], buf[1]), nil
}

func NewMethodSelectionReply(ver, method byte) *MethodSelectionReply {
	return &MethodSelectionReply{
		VER:    ver,
		METHOD: method,
	}
}

func (rep *MethodSelectionReply) Build() []byte {
	buf := make([]byte, 2)
	buf[0] = rep.VER
	buf[1] = rep.METHOD
	return buf
}

func ParseUsernamePasswordRequest(buf []byte) (*UsernamePasswordRequest, error) {
	if len(buf) < 5 {
		return nil, ErrInvalidMessage
	}
	ver := buf[0]
	ulen := buf[1]
	if ulen == 0 || len(buf) < int(4+ulen) {
		return nil, ErrInvalidMessage
	}
	uname := string(buf[2 : 2+ulen])
	plen := buf[2+ulen]
	if plen == 0 || len(buf) != int(3+ulen+plen) {
		return nil, ErrInvalidMessage
	}
	passwd := string(buf[3+ulen:])
	return NewUsernamePasswordRequest(ver, uname, passwd), nil
}

func NewUsernamePasswordRequest(ver byte, username, password string) *UsernamePasswordRequest {
	return &UsernamePasswordRequest{
		VER:    ver,
		ULEN:   byte(len(username)),
		UNAME:  username,
		PLEN:   byte(len(password)),
		PASSWD: password,
	}
}

func (req *UsernamePasswordRequest) Build() []byte {
	buf := make([]byte, 3+req.ULEN+req.PLEN)
	buf[0] = req.VER
	buf[1] = req.ULEN
	for i := 0; i < len(req.UNAME); i++ {
		buf[2+i] = req.UNAME[i]
	}
	buf[2+req.ULEN] = req.PLEN
	for i := 0; i < len(req.PASSWD); i++ {
		buf[3+int(req.ULEN)+i] = req.PASSWD[i]
	}
	return buf
}

func ParseUsernamePasswordReply(buf []byte) (*UsernamePasswordReply, error) {
	if len(buf) != 2 {
		return nil, ErrInvalidMessage
	}
	return NewUsernamePasswordReply(buf[0], buf[1]), nil
}

func NewUsernamePasswordReply(ver, status byte) *UsernamePasswordReply {
	return &UsernamePasswordReply{
		VER:    ver,
		STATUS: status,
	}
}

func (rep *UsernamePasswordReply) Build() []byte {
	buf := make([]byte, 2)
	buf[0] = rep.VER
	buf[1] = rep.STATUS
	return buf
}

func parseAddrPort(buf []byte) (byte, string, uint16, []byte, error) {
	if len(buf) < 1 {
		return 0, "", 0, nil, ErrInvalidMessage
	}
	var addr string
	var port uint16
	atype := buf[0]
	if atype == ATypeIPv4 {
		if len(buf) < 7 {
			return atype, addr, port, nil, ErrInvalidMessage
		}
		addr = net.IP(buf[1:5]).String()
		buf = buf[5:]
	} else if atype == ATypeIPv6 {
		if len(buf) < 19 {
			return atype, addr, port, nil, ErrInvalidMessage
		}
		addr = net.IP(buf[1:17]).String()
		buf = buf[17:]
	} else if atype == ATypeDomain {
		length := buf[1]
		if len(buf) < 4+int(length) {
			return atype, addr, port, nil, ErrInvalidMessage
		}
		addr = string(buf[2:(2 + length)])
		buf = buf[(2 + length):]
	} else {
		return atype, addr, port, nil, ErrInvalidMessage
	}
	binary.Read(bytes.NewReader(buf), binary.BigEndian, &port)
	return atype, addr, port, buf[2:], nil
}

func buildAddrPort(atype byte, addr string, port uint16) []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, atype)
	if atype == ATypeDomain {
		binary.Write(&buf, binary.BigEndian, byte(len(addr)))
		binary.Write(&buf, binary.BigEndian, []byte(addr))
	} else {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil
		}
		binary.Write(&buf, binary.BigEndian, []byte(ip))
	}
	binary.Write(&buf, binary.BigEndian, port)
	return buf.Bytes()
}

func ParseSocks5Request(buf []byte) (*Socks5Request, error) {
	if len(buf) < 7 {
		return nil, ErrInvalidMessage
	}
	ver := buf[0]
	cmd := buf[1]
	atype, addr, port, buf, err := parseAddrPort(buf[3:])
	if err != nil {
		return nil, err
	}
	req := NewSocks5Request(ver, cmd, atype, addr, port)
	req.BUF = buf
	return req, nil
}

func NewSocks5Request(ver, cmd, atype byte, addr string, port uint16) *Socks5Request {
	return &Socks5Request{
		VER:  ver,
		CMD:  cmd,
		ATYP: atype,
		ADDR: addr,
		PORT: port,
	}
}

func (req *Socks5Request) Build() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, req.VER)
	binary.Write(&buf, binary.BigEndian, req.CMD)
	binary.Write(&buf, binary.BigEndian, uint8(0))
	binary.Write(&buf, binary.BigEndian, buildAddrPort(req.ATYP, req.ADDR, req.PORT))
	return buf.Bytes()
}

func ParseSocks5Reply(buf []byte) (*Socks5Reply, error) {
	if len(buf) < 7 {
		return nil, ErrInvalidMessage
	}
	ver := buf[0]
	rep := buf[1]
	atype, addr, port, buf, err := parseAddrPort(buf[3:])
	if err != nil {
		return nil, err
	}
	reply := NewSocks5Reply(ver, rep, atype, addr, port)
	reply.BUF = buf
	return reply, nil
}

func NewSocks5Reply(ver, rep, atype byte, addr string, port uint16) *Socks5Reply {
	return &Socks5Reply{
		VER:  ver,
		REP:  rep,
		ATYP: atype,
		ADDR: addr,
		PORT: port,
	}
}

func (rep *Socks5Reply) Build() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, rep.VER)
	binary.Write(&buf, binary.BigEndian, rep.REP)
	binary.Write(&buf, binary.BigEndian, uint8(0))
	binary.Write(&buf, binary.BigEndian, buildAddrPort(rep.ATYP, rep.ADDR, rep.PORT))
	return buf.Bytes()
}

func ParseSocks5UDPMessage(buf []byte) (*Socks5UDPMessage, error) {
	if len(buf) < 7 {
		return nil, ErrInvalidMessage
	}
	frag := buf[2]
	atype, addr, port, buf, err := parseAddrPort(buf[3:])
	if err != nil {
		return nil, err
	}
	return NewSOCKSUDPMessage(frag, atype, addr, port, buf), nil
}

func NewSOCKSUDPMessage(frag, atype byte, addr string, port uint16, data []byte) *Socks5UDPMessage {
	return &Socks5UDPMessage{
		FRAG: frag,
		ATYP: atype,
		ADDR: addr,
		PORT: port,
		DATA: data,
	}
}

func (m *Socks5UDPMessage) Build() []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, uint16(0x0))
	binary.Write(&buf, binary.BigEndian, m.FRAG)
	binary.Write(&buf, binary.BigEndian, buildAddrPort(m.ATYP, m.ADDR, m.PORT))
	binary.Write(&buf, binary.BigEndian, m.DATA)
	return buf.Bytes()
}
