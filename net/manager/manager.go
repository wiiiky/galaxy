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
package manager

import (
	"galaxy/net/tunnel"
	"sync"
	"time"
)

type TunnelManager struct {
	sync.Mutex
	tunnels []tunnel.Tunnel
}

func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		tunnels: nil,
	}
}

func (tm *TunnelManager) addTunnel(tunnel tunnel.Tunnel) {
	defer tm.Unlock()
	tm.Lock()
	tm.tunnels = append(tm.tunnels, tunnel)
}

func (tm *TunnelManager) AddSSLocalTunnel(address, addr string, port uint16, method, password string) (tunnel.Tunnel, error) {
	tunnel, err := tunnel.NewSSLocalTunnel(address, addr, port, method, password)
	if err != nil {
		return nil, err
	}
	tm.addTunnel(tunnel)
	return tunnel, nil
}

func (tm *TunnelManager) AddSSRemoteTunnel(address, method, password string) (tunnel.Tunnel, error) {
	tunnel, err := tunnel.NewSSRemoteTunnel(address, method, password)
	if err != nil {
		return nil, err
	}
	tm.addTunnel(tunnel)
	return tunnel, nil
}

func (tm *TunnelManager) Run() {
	for {
		time.Sleep(100 * time.Second)
	}
}
