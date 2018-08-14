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

type newEncrypterFunc func([]byte, []byte) Encrypter
type newDecrypterFunc func([]byte, []byte) Decrypter

type Encrypter interface {
	Encrypt([]byte) []byte
}

type Decrypter interface {
	Decrypt([]byte) []byte
}

type CipherInfo struct {
	KeySize       int
	IvSize        int
	EncrypterFunc newEncrypterFunc
	DecrypterFunc newDecrypterFunc
}

var (
	cipherInfos = map[string]*CipherInfo{
		"aes-128-cfb": &CipherInfo{16, 16, newAESCFBEncrypter, newAESCFBDecrypter},
		"aes-192-cfb": &CipherInfo{24, 16, newAESCFBEncrypter, newAESCFBDecrypter},
		"aes-256-cfb": &CipherInfo{32, 16, newAESCFBEncrypter, newAESCFBDecrypter},
		"rc4-md5":     &CipherInfo{16, 16, newRC4MD5Encrypter, newRC4MD5Decrypter},
		"salsa20":     &CipherInfo{32, 8, newSalsa20Encrypter, newSalsa20Decrypter},
		"chacha20":    &CipherInfo{32, 8, newChacha20Encrypter, newChacha20Decrypter},
		"none":        &CipherInfo{0, 0, newNoneEncrypter, newNoneDecrypter},
		"not":         &CipherInfo{0, 0, newNotEncrypter, newNotDecrypter},
	}
)

func GetCipherInfo(name string) *CipherInfo {
	info := cipherInfos[name]
	return info
}
