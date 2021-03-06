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
	"net"
)

type Conn struct {
	net.Conn
}

func NewConn(c net.Conn) *Conn {
	return &Conn{
		Conn: c,
	}
}

func (c *Conn) Write(data []byte) (int, error) {
	total := len(data)
	written := 0
	for written < total {
		if n, err := c.Conn.Write(data[written:]); err != nil {
			return written, err
		} else {
			written += n
		}
	}
	return written, nil
}

func Dial(network, address string) (*Conn, error) {
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return &Conn{
		Conn: c,
	}, nil
}

type TConn struct {
	conn *Conn
}

func NewTConn(c *Conn) *TConn {
	return &TConn{
		conn: c,
	}
}

func (t *TConn) Read() ([]byte, error) {
	buf := make([]byte, 4096)
	if n, err := t.conn.Read(buf); err != nil {
		return nil, err
	} else {
		return buf[:n], nil
	}
}

func (t *TConn) Write(data []byte) error {
	_, err := t.conn.Write(data)
	return err
}

func (t *TConn) Close() {
	defer t.conn.Close()
}

type IConn interface {
	Read() ([]byte, error)
	Write([]byte) error
}
