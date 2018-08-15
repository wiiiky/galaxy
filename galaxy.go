package main

import (
	"galaxy/net/manager"
)

func main() {
	tm := manager.NewTunnelManager()
	t, _ := tm.AddSSLocalTunnel("0.0.0.0:11111", "127.0.0.1", 22222, "aes-256-cfb", "abcdefg")
	go t.Run()
	t, _ = tm.AddSSRemoteTunnel("0.0.0.0:22222", "aes-256-cfb", "abcdefg")
	go t.Run()
	tm.Run()
}
