package main

import (
	"fmt"
	"galaxy/net/tunnel"
)

func main() {
	listener, err := tunnel.NewSocks5Listener("tcp", "0.0.0.0:11111")
	if err != nil {
		panic(err)
	}
	for {
		if sc, err := listener.Accept(); err != nil {
			panic(err)
		} else {
			go runTunnel(sc)
		}
	}
}

func runTunnel(sc *tunnel.Socks5SConn) {
	defer sc.Close()
	addr, port, err := sc.Start()
	if err != nil {
		return
	}
	c, err := tunnel.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
	sc.Notify(addr, port, err == nil)
	if err != nil {
		return
	}
	defer c.Close()

	chan1 := make(chan []byte, 1024)
	chan2 := make(chan []byte, 1024)
	go func() {
		defer close(chan1)
		for {
			if data, err := sc.Read(); err != nil {
				break
			} else {
				chan1 <- data
			}
		}
	}()
	go func() {
		defer close(chan2)
		for {
			data := make([]byte, 4096)
			if n, err := c.Read(data); err != nil {
				break
			} else {
				chan2 <- data[:n]
			}
		}
	}()

LOOP:
	for {
		select {
		case data, ok := <-chan1:
			{
				if !ok {
					break LOOP
				}
				if _, err := c.Write(data); err != nil {
					break LOOP
				}
			}
		case data, ok := <-chan2:
			{
				if !ok {
					break LOOP
				}
				if err := sc.Write(data); err != nil {
					break LOOP
				}
			}
		}
	}
}
