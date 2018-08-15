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

package tconn

import (
	"fmt"
	"galaxy/cipher"
	"galaxy/protocol/socks"
	"galaxy/protocol/ss"
	"net"
	"strings"
)

type SSListener struct {
	netListener net.Listener
	method      string
	password    string
	cipherInfo  *cipher.CipherInfo
}

func NewSSListener(address, method, password string) (*SSListener, error) {
	cipherInfo := cipher.GetCipherInfo(strings.ToLower(method))
	if cipherInfo == nil {
		return nil, fmt.Errorf("Method %s Not Found", method)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &SSListener{
		netListener: listener,
		method:      method,
		password:    password,
		cipherInfo:  cipherInfo,
	}, nil
}

func (l *SSListener) Close() {
	defer l.netListener.Close()
}

func (l *SSListener) Accept() (*SSRConn, error) {
	c, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	key := ss.CreateKey(l.password, l.cipherInfo.KeySize)
	iv := cipher.RandKey(l.cipherInfo.IvSize)
	encrypter := l.cipherInfo.EncrypterFunc(key, iv)
	return &SSRConn{
		TConn: TConn{
			conn: &Conn{
				Conn: c,
			},
		},
		cipherInfo: l.cipherInfo,
		encrypter:  encrypter,
		decrypter:  nil,
		key:        key,
		iv:         iv,
		ivSent:     false,
		buf:        nil,
	}, nil
}

type SSRConn struct {
	TConn
	cipherInfo *cipher.CipherInfo
	encrypter  cipher.Encrypter
	decrypter  cipher.Decrypter
	key        []byte
	iv         []byte
	buf        []byte
	ivSent     bool
}

func (ssc *SSRConn) Start() (string, uint16, error) {
	if ssc.decrypter != nil {
		return "", 0, nil
	}
	ivbuf := make([]byte, ssc.cipherInfo.IvSize)
	if _, err := ssc.conn.Read(ivbuf); err != nil {
		return "", 0, err
	}
	ssc.decrypter = ssc.cipherInfo.DecrypterFunc(ssc.key, ivbuf)

	data, err := ssc.Read()
	if err != nil {
		return "", 0, err
	}
	req, err := ss.ParseAddressRequest(data)
	if err != nil {
		return "", 0, err
	}
	ssc.buf = req.BUF
	return req.ADDR, req.PORT, nil
}

func (ssc *SSRConn) Read() ([]byte, error) {
	if len(ssc.buf) > 0 {
		buf := ssc.buf
		ssc.buf = nil
		return buf, nil
	}

	if data, err := ssc.TConn.Read(); err != nil {
		return nil, err
	} else {
		return ssc.decrypter.Decrypt(data), nil
	}
}

func (ssc *SSRConn) Write(data []byte) error {
	if !ssc.ivSent {
		ssc.TConn.Write(ssc.iv)
		ssc.ivSent = true
	}
	return ssc.TConn.Write(ssc.encrypter.Encrypt(data))
}

/*
 * ShadowSocks Client Connection
 */
type SSLConn struct {
	TConn
	cipherInfo *cipher.CipherInfo
	encrypter  cipher.Encrypter
	decrypter  cipher.Decrypter
	key        []byte
	iv         []byte
}

/* 连接Shadowsocks服务 */
func SSDial(addr string, port uint16, method, password string) (*SSLConn, error) {
	cipherInfo := cipher.GetCipherInfo(strings.ToLower(method))
	if cipherInfo == nil {
		return nil, fmt.Errorf("Method %s Not Found", method)
	}
	key := ss.CreateKey(password, cipherInfo.KeySize)
	iv := cipher.RandKey(cipherInfo.IvSize)
	encrypter := cipherInfo.EncrypterFunc(key, iv)

	c, err := Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return nil, err
	}
	return &SSLConn{
		TConn: TConn{
			conn: c,
		},
		cipherInfo: cipherInfo,
		encrypter:  encrypter,
		key:        key,
		iv:         iv,
	}, nil
}

func (ssc *SSLConn) Start(addr string, port uint16) error {
	atype := socks.GetAddrAType(addr)
	req := ss.NewAddressRequest(atype, addr, port)
	if len(ssc.iv) != 0 {
		if _, err := ssc.conn.Write(ssc.iv); err != nil {
			return err
		}
	}
	if err := ssc.Write(req.Build()); err != nil {
		return err
	}
	return nil
}

func (ssc *SSLConn) Write(data []byte) error {
	return ssc.TConn.Write(ssc.encrypter.Encrypt(data))
}

func (ssc *SSLConn) Read() ([]byte, error) {
	if ssc.decrypter == nil {
		ivbuf := make([]byte, ssc.cipherInfo.IvSize)
		if _, err := ssc.conn.Read(ivbuf); err != nil {
			return nil, err
		}
		ssc.decrypter = ssc.cipherInfo.DecrypterFunc(ssc.key, ivbuf)
	}
	if data, err := ssc.TConn.Read(); err != nil {
		return nil, err
	} else {
		return ssc.decrypter.Decrypt(data), nil
	}
}
