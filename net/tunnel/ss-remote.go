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
package tunnel

import (
	"fmt"
	"galaxy/net/tunnel/tconn"
)

/*  Shadowsocks 服务端 */
type SSRemoteTunnel struct {
	listener *tconn.SSListener
	signal   chan bool
	method   string
	password string
	running  bool
}

func (t *SSRemoteTunnel) IsRunning() bool {
	return t.running
}

func (t *SSRemoteTunnel) Name() string {
	return "Remote"
}

func NewSSRemoteTunnel(address, method, password string) (*SSRemoteTunnel, error) {
	listener, err := tconn.NewSSListener(address, method, password)
	if err != nil {
		return nil, err
	}
	return &SSRemoteTunnel{
		listener: listener,
		signal:   make(chan bool, 1),
		method:   method,
		password: password,
		running:  false,
	}, nil
}

func (t *SSRemoteTunnel) runSSRemote(ssc *tconn.SSRConn) {
	defer ssc.Close()
	addr, port, err := ssc.Start()
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	c, err := tconn.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	tc := tconn.NewTConn(c)
	defer tc.Close()
	c1 := make(chan []byte, 1024)
	c2 := make(chan []byte, 1024)
	go TConnChanel(ssc, c1)
	go TConnChanel(tc, c2)
LOOP:
	for {
		select {
		case data, ok := <-c1:
			if !ok {
				break LOOP
			} else if err := tc.Write(data); err != nil {
				break LOOP
			}
		case data, ok := <-c2:
			if !ok {
				break LOOP
			} else if err := ssc.Write(data); err != nil {
				break LOOP
			}
		}
	}
}

func (t *SSRemoteTunnel) Quit() {
	t.signal <- true
}

func (t *SSRemoteTunnel) end() {
	t.running = false
	t.listener.Close()
}

func (t *SSRemoteTunnel) Run() {
	defer t.end()
	t.running = true

	cc := make(chan *tconn.SSRConn, 128)
	go func() {
		defer close(cc)
		for {
			if c, err := t.listener.Accept(); err != nil {
				break
			} else {
				cc <- c
			}
		}
	}()
LOOP:
	for {
		select {
		case quit, _ := <-t.signal:
			{
				if quit {
					break LOOP
				}
			}
		case c, ok := <-cc:
			{
				if !ok {
					break LOOP
				}
				go t.runSSRemote(c)
			}
		}
	}
}
