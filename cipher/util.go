/*
 * Copyright (C) 2015 - 2017 Wiky Lyu
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

package cipher

import (
	"crypto/cipher"
	"crypto/rand"
)

func cipherStreamXOR(stream cipher.Stream, data []byte) []byte {
	if data == nil || len(data) == 0 {
		return nil
	}
	stream.XORKeyStream(data, data)
	return data
}

/* 创建随机字符串 */
func RandKey(l int) []byte {
	if l <= 0 {
		return nil
	}
	key := make([]byte, l)
	rand.Read(key)
	return key
}
