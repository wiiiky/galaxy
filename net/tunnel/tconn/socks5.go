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
	"galaxy/protocol/socks"
	"net"
)

type Socks5Listener struct {
	netListener net.Listener
	uname       string
	passwd      string
}

/*
 * Socks5 Server Conn
 */
type Socks5SConn struct {
	TConn
	uname  string
	passwd string

	reqBuf []byte
}

func NewSocks5Listener(address string) (*Socks5Listener, error) {
	netListener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &Socks5Listener{
		netListener: netListener,
	}, nil
}

func (l *Socks5Listener) Close() {
	defer l.netListener.Close()
}

func (l *Socks5Listener) SetAuth(uname, passwd string) {
	l.uname = uname
	l.passwd = passwd
}

func (l *Socks5Listener) Accept() (*Socks5SConn, error) {
	netConn, err := l.netListener.Accept()
	if err != nil {
		return nil, err
	}
	return &Socks5SConn{
		TConn: TConn{
			conn: NewConn(netConn),
		},
		uname:  l.uname,
		passwd: l.passwd,
	}, nil
}

func (sc *Socks5SConn) doMethodSelection() (byte, error) {
	buf := make([]byte, 256)
	conn := sc.conn
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	req, err := socks.ParseMethodSelectionRequest(buf[:n])
	if err != nil {
		return 0, err
	} else if req.VER != socks.Version5 {
		return 0, fmt.Errorf("Invalid Version %d", req.VER)
	}
	method := socks.MethodNoAuthRequired
	if sc.uname != "" && sc.passwd != "" {
		method = socks.MethodUsernamePassword
	}
	rep := socks.NewMethodSelectionReply(socks.Version5, socks.MethodNoAcceptable)
	for _, m := range req.METHODS {
		if m == method {
			rep.METHOD = method
			break
		}
	}
	if _, err := conn.Write(rep.Build()); err != nil {
		return 0, err
	} else if rep.METHOD == socks.MethodNoAcceptable {
		return 0, fmt.Errorf("No Acceptable Method")
	}
	return rep.METHOD, nil
}

func (sc *Socks5SConn) doUsernamePassword() error {
	buf := make([]byte, 1024)
	conn := sc.conn
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	req, err := socks.ParseUsernamePasswordRequest(buf[:n])
	if err != nil {
		return err
	}
	passed := req.UNAME == sc.uname && req.PASSWD == sc.passwd
	status := socks.UsernamePasswordStatusSuccess
	if !passed {
		status = socks.UsernamePasswordStatusFailure
	}
	rep := socks.NewUsernamePasswordReply(socks.Version5, status)
	if _, err := conn.Write(rep.Build()); err != nil {
		return err
	} else if !passed {
		return fmt.Errorf("Invalid Username/Password")
	}
	return nil
}

func (sc *Socks5SConn) doCMDRequest() (string, uint16, error) {
	buf := make([]byte, 2048)
	conn := sc.conn
	n, err := conn.Read(buf)
	if err != nil {
		return "", 0, err
	}
	req, err := socks.ParseSocks5Request(buf[:n])
	if err != nil {
		return "", 0, err
	}
	if req.CMD == socks.CMDConnect {
		sc.reqBuf = req.BUF
	} else {
		return "", 0, fmt.Errorf("Invalid Command %d", req.CMD)
	}
	return req.ADDR, req.PORT, nil
}

/* 执行SOCKS5协议的初始化过程 */
func (sc *Socks5SConn) Start() (string, uint16, error) {
	if method, err := sc.doMethodSelection(); err != nil {
		return "", 0, err
	} else if method == socks.MethodUsernamePassword {
		if err := sc.doUsernamePassword(); err != nil {
			return "", 0, err
		}
	}
	return sc.doCMDRequest()
}

func (sc *Socks5SConn) Notify(addr string, port uint16, success bool) error {
	atype := socks.ATypeDomain
	if ip := net.ParseIP(addr); ip != nil {
		if len(ip) == 4 {
			atype = socks.ATypeIPv4
		} else {
			atype = socks.ATypeIPv6
		}
	}
	status := socks.ReplySuccess
	if !success {
		status = socks.ReplyGeneralFailure
	}
	rep := socks.NewSocks5Reply(socks.Version5, status, atype, addr, port)
	if _, err := sc.conn.Write(rep.Build()); err != nil {
		return err
	}
	return nil
}

func (sc *Socks5SConn) Read() ([]byte, error) {
	if len(sc.reqBuf) != 0 {
		buf := sc.reqBuf
		sc.reqBuf = nil
		return buf, nil
	}
	return sc.TConn.Read()
}
