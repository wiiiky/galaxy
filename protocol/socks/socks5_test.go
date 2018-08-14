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
	"testing"
)

func testMethodSelectionRequest(t *testing.T, ver uint8, methods ...uint8) {
	buf := make([]byte, 2+len(methods))
	buf[0] = ver
	buf[1] = uint8(len(methods))
	for i, v := range methods {
		buf[2+i] = byte(v)
	}

	req, err := ParseMethodSelectionRequest(buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.VER != ver {
		t.Fatal("Wrong VER")
	} else if int(req.NMETHODS) != len(methods) {
		t.Fatal("Wrong NMETHODS")
	} else if len(req.METHODS) != len(methods) {
		t.Fatal("Wrong METHODS")
	} else {
		for i, _ := range methods {
			if req.METHODS[i] != methods[i] {
				t.Fatal("Wrong METHODS")
			}
		}
	}
	if bytes.Compare(buf, req.Build()) != 0 {
		t.Fatal("Build Error")
	}

	if bytes.Compare(buf, NewMethodSelectionRequest(ver, methods...).Build()) != 0 {
		t.Fatal("New Error")
	}
}

func TestMethodSelectionRequest(t *testing.T) {
	buf := []byte("\x05\x01")
	_, err := ParseMethodSelectionRequest(buf)
	if err == nil {
		t.Fatal("Parse Error")
	}
	testMethodSelectionRequest(t, Version5, MethodUsernamePassword, MethodGSSAPI)
	testMethodSelectionRequest(t, Version5, MethodNoAuthRequired)
	testMethodSelectionRequest(t, Version4, MethodNoAuthRequired, MethodUsernamePassword, MethodGSSAPI)
}

func testMethodSelectionReply(t *testing.T, ver, method uint8) {
	buf := make([]byte, 2)
	buf[0] = ver
	buf[1] = method

	rep, err := ParseMethodSelectionReply(buf)
	if err != nil {
		t.Fatal(err)
	}
	if rep.VER != ver {
		t.Fatal("Wrong VER")
	} else if rep.METHOD != method {
		t.Fatal("Wrong METHOD")
	}
	if bytes.Compare(buf, rep.Build()) != 0 {
		t.Fatal("Build Error")
	}

	if bytes.Compare(buf, NewMethodSelectionReply(ver, method).Build()) != 0 {
		t.Fatal("New Error")
	}
}

func TestMethodSelectionReply(t *testing.T) {
	buf := []byte("\x05")
	_, err := ParseMethodSelectionReply(buf)
	if err == nil {
		t.Fatal("Parse Error")
	}
	testMethodSelectionReply(t, Version5, MethodGSSAPI)
	testMethodSelectionReply(t, Version4, MethodNoAcceptable)
	testMethodSelectionReply(t, Version5, MethodNoAuthRequired)
}

func testUsernamePasswordRequest(t *testing.T, ver byte, username, password string) {
	buf := make([]byte, 3+len(username)+len(password))
	buf[0] = ver
	buf[1] = byte(len(username))
	for i := 0; i < len(username); i++ {
		buf[2+i] = username[i]
	}
	buf[2+len(username)] = byte(len(password))
	for i := 0; i < len(password); i++ {
		buf[3+len(username)+i] = password[i]
	}
	req, err := ParseUsernamePasswordRequest(buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.VER != ver {
		t.Fatal("Wrong VER")
	} else if req.UNAME != username || int(req.ULEN) != len(username) {
		t.Fatal("Wrong UNAME")
	} else if req.PASSWD != password || int(req.PLEN) != len(password) {
		t.Fatal("Wrong PASSWD")
	}

	if bytes.Compare(buf, req.Build()) != 0 {
		panic("Build Error")
	}
	if bytes.Compare(buf, NewUsernamePasswordRequest(ver, username, password).Build()) != 0 {
		panic("New Error")
	}
}

func TestUsernamePasswordRequest(t *testing.T) {
	buf := []byte("\x05\x00\x00\x00\x00")
	_, err := ParseMethodSelectionReply(buf)
	if err == nil {
		t.Fatal("Parse Error")
	}
	testUsernamePasswordRequest(t, Version5, "ABC", "123")
	testUsernamePasswordRequest(t, Version4, "ABCD", "1235")
	testUsernamePasswordRequest(t, Version5, "AB", "12你好")
}

func testUsernamePasswordReply(t *testing.T, ver, status uint8) {
	buf := make([]byte, 2)
	buf[0] = ver
	buf[1] = status

	rep, err := ParseUsernamePasswordReply(buf)
	if err != nil {
		t.Fatal(err)
	}
	if rep.VER != ver {
		t.Fatal("Wrong VER")
	} else if rep.STATUS != status {
		t.Fatal("Wrong METHOD")
	}
	if bytes.Compare(buf, rep.Build()) != 0 {
		t.Fatal("Build Error")
	}

	if bytes.Compare(buf, NewMethodSelectionReply(ver, status).Build()) != 0 {
		t.Fatal("New Error")
	}
}

func TestUsernamePasswordReply(t *testing.T) {
	buf := []byte("\x05")
	_, err := ParseUsernamePasswordReply(buf)
	if err == nil {
		t.Fatal("Parse Error")
	}
	testUsernamePasswordReply(t, Version5, UsernamePasswordStatusSuccess)
	testUsernamePasswordReply(t, Version4, UsernamePasswordStatusFailure)
}

func testSOCKSRequest(t *testing.T, ver, cmd, atype byte, addr string, port uint16) {
	req := NewSocks5Request(ver, cmd, atype, addr, port)
	if req == nil {
		t.Fatal("New Error")
	}
	if req.VER != ver {
		t.Fatal("Wrong VER")
	} else if req.CMD != cmd {
		t.Fatal("Wrong CMD")
	} else if req.ATYP != atype {
		t.Fatal("Wrong ATYP")
	} else if req.PORT != port {
		t.Fatal("Wrong PORT")
	}
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, ver)
	binary.Write(&buf, binary.BigEndian, cmd)
	binary.Write(&buf, binary.BigEndian, byte(0x0))
	binary.Write(&buf, binary.BigEndian, atype)
	if atype == ATypeDomain {
		binary.Write(&buf, binary.BigEndian, byte(len(addr)))
		binary.Write(&buf, binary.BigEndian, []byte(addr))
	} else {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatal("Invalid IP")
		}
		binary.Write(&buf, binary.BigEndian, []byte(ip))
	}
	binary.Write(&buf, binary.BigEndian, port)
	if bytes.Compare(buf.Bytes(), req.Build()) != 0 {
		t.Fatal("Compare Error")
	}
}

func TestSOCKSRequest(t *testing.T) {
	testSOCKSRequest(t, Version5, CMDConnect, ATypeDomain, "www.baidu.com", 80)
	testSOCKSRequest(t, Version5, CMDConnect, ATypeDomain, "www.google.com", 443)
	testSOCKSRequest(t, Version4, CMDBind, ATypeIPv4, "127.0.0.1", 12345)
	testSOCKSRequest(t, Version4, CMDUDPAssociate, ATypeIPv6, "::1", 23456)
}

func testSOCKSReply(t *testing.T, ver, rep, atype byte, addr string, port uint16) {
	req := NewSocks5Reply(ver, rep, atype, addr, port)
	if req == nil {
		t.Fatal("New Error")
	}
	if req.VER != ver {
		t.Fatal("Wrong VER")
	} else if req.REP != rep {
		t.Fatal("Wrong REP")
	} else if req.ATYP != atype {
		t.Fatal("Wrong ATYP")
	} else if req.PORT != port {
		t.Fatal("Wrong PORT")
	}
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, ver)
	binary.Write(&buf, binary.BigEndian, rep)
	binary.Write(&buf, binary.BigEndian, byte(0x0))
	binary.Write(&buf, binary.BigEndian, atype)
	if atype == ATypeDomain {
		binary.Write(&buf, binary.BigEndian, byte(len(addr)))
		binary.Write(&buf, binary.BigEndian, []byte(addr))
	} else {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatal("Invalid IP")
		}
		binary.Write(&buf, binary.BigEndian, []byte(ip))
	}
	binary.Write(&buf, binary.BigEndian, port)
	if bytes.Compare(buf.Bytes(), req.Build()) != 0 {
		t.Fatal("Compare Error")
	}
}

func TestSOCKSReply(t *testing.T) {
	testSOCKSReply(t, Version5, ReplySuccess, ATypeDomain, "www.baidu.com", 80)
	testSOCKSReply(t, Version5, ReplyAddressTypeNotSupported, ATypeDomain, "www.google.com", 443)
	testSOCKSReply(t, Version4, ReplyConnectionRefused, ATypeIPv4, "127.0.0.1", 12345)
	testSOCKSReply(t, Version4, ReplyGeneralFailure, ATypeIPv6, "::1", 23456)
}

func testSOCKSUDPMessage(t *testing.T, frag, atype byte, addr string, port uint16, data []byte) {
	m := NewSOCKSUDPMessage(frag, atype, addr, port, data)
	if m.FRAG != frag {
		t.Fatal("Wrong FRAG")
	} else if m.ATYP != atype {
		t.Fatal("Wrong ATYP")
	} else if m.ADDR != addr {
		t.Fatal("Wrong ADDR")
	} else if m.PORT != port {
		t.Fatal("Wrong PORT")
	} else if bytes.Compare(m.DATA, data) != 0 {
		t.Fatal("Wrong DATA")
	}
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, frag)
	binary.Write(&buf, binary.BigEndian, atype)
	if atype == ATypeDomain {
		binary.Write(&buf, binary.BigEndian, byte(len(addr)))
		binary.Write(&buf, binary.BigEndian, []byte(addr))
	} else {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatal("Invalid IP")
		}
		binary.Write(&buf, binary.BigEndian, []byte(ip))
	}
	binary.Write(&buf, binary.BigEndian, port)
	binary.Write(&buf, binary.BigEndian, data)
	if bytes.Compare(buf.Bytes(), m.Build()) != 0 {
		t.Fatal("Compare Error")
	}
}

func TestSOCKSUDPMessage(t *testing.T) {
	testSOCKSUDPMessage(t, 1, ATypeDomain, "www.baidu.com", 80, []byte("abc"))
	testSOCKSUDPMessage(t, 2, ATypeDomain, "www.google.com", 443, []byte("你好"))
	testSOCKSUDPMessage(t, 3, ATypeIPv4, "127.0.0.1", 12345, []byte("Jim 什么？"))
	testSOCKSUDPMessage(t, 4, ATypeIPv6, "::1", 23456, []byte("AAAA"))
}
