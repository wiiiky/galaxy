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

type SSLocalTunnel struct {
	listener *tconn.Socks5Listener
	signal   chan bool
	addr     string
	port     uint16
	method   string
	password string
	running  bool
}

func (t *SSLocalTunnel) Name() string {
	return "Local"
}

func (t *SSLocalTunnel) IsRunning() bool {
	return t.running
}

func NewSSLocalTunnel(address, addr string, port uint16, method, password string) (*SSLocalTunnel, error) {
	listener, err := tconn.NewSocks5Listener(address)
	if err != nil {
		return nil, err
	}
	return &SSLocalTunnel{
		listener: listener,
		signal:   make(chan bool, 1),
		addr:     addr,
		port:     port,
		method:   method,
		password: password,
		running:  false,
	}, nil
}

func (t *SSLocalTunnel) Quit() {
	t.signal <- true
}

func (t *SSLocalTunnel) end() {
	t.running = false
	t.listener.Close()
}

func (t *SSLocalTunnel) runSSLocal(sc *tconn.Socks5SConn) {
	defer sc.Close()
	addr, port, err := sc.Start()
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	ssc, err := tconn.SSDial(t.addr, t.port, t.method, t.password)
	sc.Notify(addr, port, err == nil)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer ssc.Close()
	if err := ssc.Start(addr, port); err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	c1 := make(chan []byte, 1024)
	c2 := make(chan []byte, 1024)
	go TConnChanel(sc, c1)
	go TConnChanel(ssc, c2)
LOOP:
	for {
		select {
		case data, ok := <-c1:
			{
				if !ok {
					break LOOP
				} else if err := ssc.Write(data); err != nil {
					break LOOP
				}
			}
		case data, ok := <-c2:
			{
				if !ok {
					break LOOP
				} else if err := sc.Write(data); err != nil {
					break LOOP
				}
			}
		}
	}
}

func (t *SSLocalTunnel) Run() {
	defer t.end()
	t.running = true

	cc := make(chan *tconn.Socks5SConn, 128)
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
				go t.runSSLocal(c)
			}
		}
	}
}
