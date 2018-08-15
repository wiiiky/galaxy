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

package ss

import (
	"galaxy/protocol/socks"
	"testing"
)

func testAddressRequest(t *testing.T, atype byte, addr string, port uint16) {
	req := NewAddressRequest(atype, addr, port)
	if req.ATYP != atype {
		t.Fatal("Wrong ATYP")
	} else if req.ADDR != addr {
		t.Fatal("Wrong ADDR")
	} else if req.PORT != port {
		t.Fatal("Wrong PORT")
	}
}

func TestAddressRequest(t *testing.T) {
	testAddressRequest(t, socks.ATypeIPv4, "127.0.0.1", 1234)
	testAddressRequest(t, socks.ATypeDomain, "www.baidu.com", 2334)
	testAddressRequest(t, socks.ATypeIPv6, "::1", 22311)
}
