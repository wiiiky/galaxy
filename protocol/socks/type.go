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
	"errors"
)

/*
 *  Socks5 协议
 * https://www.ietf.org/rfc/rfc1928.txt
 */

const (
	Version5 = byte(0x5)
	Version4 = byte(0x4)
)

const (
	MethodNoAuthRequired   = byte(0x0)
	MethodGSSAPI           = byte(0x1)
	MethodUsernamePassword = byte(0x2)
	MethodNoAcceptable     = byte(0xff)
)

const (
	ATypeIPv4   = byte(1)
	ATypeIPv6   = byte(4)
	ATypeDomain = byte(3)
)

const (
	ReplySuccess                 = byte(0x0)
	ReplyGeneralFailure          = byte(0x1)
	ReplyConnectionNowAllowed    = byte(0x2)
	ReplyNetworkUnreachable      = byte(0x3)
	ReplyHostUnreachable         = byte(0x4)
	ReplyConnectionRefused       = byte(0x5)
	ReplyTTLExpired              = byte(0x6)
	ReplyCommandNotSupported     = byte(0x7)
	ReplyAddressTypeNotSupported = byte(0x8)
)

const (
	CMDConnect      = byte(1)
	CMDBind         = byte(2)
	CMDUDPAssociate = byte(3)
)

var (
	ErrInvalidMessage = errors.New("Invalid Message")
)

type MethodSelectionRequest struct {
	VER      byte
	NMETHODS byte
	METHODS  []byte
}

type MethodSelectionReply struct {
	VER    byte
	METHOD byte
}

const (
	UsernamePasswordStatusSuccess = byte(0x00)
	UsernamePasswordStatusFailure = byte(0x01)
)

type UsernamePasswordRequest struct {
	VER    byte
	ULEN   byte
	UNAME  string
	PLEN   byte
	PASSWD string
}

type UsernamePasswordReply struct {
	VER    byte
	STATUS byte
}

type Socks5Request struct {
	VER  byte
	CMD  byte
	RSV  byte
	ATYP byte
	ADDR string
	PORT uint16
	BUF  []byte
}

type Socks5Reply struct {
	VER  byte
	REP  byte
	RSV  byte
	ATYP byte
	ADDR string
	PORT uint16
	BUF  []byte
}

type Socks5UDPMessage struct {
	RSV  uint16
	FRAG byte
	ATYP byte
	ADDR string
	PORT uint16
	DATA []byte
}
