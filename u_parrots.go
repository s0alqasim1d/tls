// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"sort"
	"strconv"
	"time"
)

// ApplyPreset should only be used in conjunction with HelloCustom to apply custom specs.
// Also used internally.
func (uconn *UConn) ApplyPreset(p *ClientHelloSpec) error {
	hello := uconn.HandshakeState.Hello
	session := uconn.HandshakeState.Session

	if hello.Vers == 0 {
		hello.Vers = VersionTLS12
	}
	switch len(hello.Random) {
	case 0:
		hello.Random = make([]byte, 32)
		_, err := io.ReadFull(uconn.config.rand(), hello.Random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	case 32:
	// carry on
	default:
		return errors.New("ClientHello expected length: 32 bytes. Got: " +
			strconv.Itoa(len(hello.Random)) + " bytes")
	}
	if len(hello.CipherSuites) == 0 {
		hello.CipherSuites = defaultCipherSuites()
	}
	if len(hello.CompressionMethods) == 0 {
		hello.CompressionMethods = []uint8{compressionNone}
	}

	// Currently, GREASE is assumed to come from BoringSSL
	grease_bytes := make([]byte, 2*ssl_grease_last_index)
	grease_extensions_seen := 0
	_, err := io.ReadFull(uconn.config.rand(), grease_bytes)
	if err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}
	for i := range uconn.greaseSeed {
		uconn.greaseSeed[i] = binary.LittleEndian.Uint16(grease_bytes[2*i : 2*i+2])
	}
	if uconn.greaseSeed[ssl_grease_extension1] == uconn.greaseSeed[ssl_grease_extension2] {
		uconn.greaseSeed[ssl_grease_extension2] ^= 0x1010
	}

	hello.CipherSuites = p.CipherSuites
	for i := range hello.CipherSuites {
		if hello.CipherSuites[i] == GREASE_PLACEHOLDER {
			hello.CipherSuites[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_cipher)
		}
	}
	uconn.GetSessionID = p.GetSessionID

	uconn.Extensions = p.Extensions

	for _, e := range uconn.Extensions {
		switch ext := e.(type) {
		case *SNIExtension:
			if ext.ServerName == "" {
				ext.ServerName = uconn.config.ServerName
			}
		case *FakeGREASEExtension:
			switch grease_extensions_seen {
			case 0:
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1)
			case 1:
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2)
				ext.Body = []byte{0}
			default:
				return errors.New("at most 2 grease extensions are supported")
			}
			grease_extensions_seen += 1
		case *SessionTicketExtension:
			err := uconn.SetSessionState(session)
			if err != nil {
				return err
			}
		case *SupportedCurvesExtension:
			for i := range ext.Curves {
				if ext.Curves[i] == GREASE_PLACEHOLDER {
					ext.Curves[i] = CurveID(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
				}
			}
		}
	}
	return nil
}

func tossBiasedCoin(probability float32) bool {
	// probability is expected to be in [0,1]
	// this function never returns errors for ease of use
	const precision = 0xffff
	threshold := float32(precision) * probability
	value, err := getRandInt(precision)
	if err != nil {
		// I doubt that this code will ever actually be used, as other functions are expected to complain
		// about used source of entropy. Nonetheless, this is more than enough for given purpose
		return ((time.Now().Unix() & 1) == 0)
	}

	if float32(value) <= threshold {
		return true
	} else {
		return false
	}
}

func removeRandomCiphers(s []uint16, maxRemovalProbability float32) []uint16 {
	// removes elements in place
	// probability to remove increases for further elements
	// never remove first cipher
	if len(s) <= 1 {
		return s
	}

	// remove random elements
	floatLen := float32(len(s))
	sliceLen := len(s)
	for i := 1; i < sliceLen; i++ {
		if tossBiasedCoin(maxRemovalProbability * float32(i) / floatLen) {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s
}

func getRandInt(max int) (int, error) {
	bigInt, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(bigInt.Int64()), err
}

func getRandPerm(n int) ([]int, error) {
	permArray := make([]int, n)
	for i := 1; i < n; i++ {
		j, err := getRandInt(i + 1)
		if err != nil {
			return permArray, err
		}
		permArray[i] = permArray[j]
		permArray[j] = i
	}
	return permArray, nil
}

func shuffledCiphers() ([]uint16, error) {
	ciphers := make(sortableCiphers, len(cipherSuites))
	perm, err := getRandPerm(len(cipherSuites))
	if err != nil {
		return nil, err
	}
	for i, suite := range cipherSuites {
		ciphers[i] = sortableCipher{suite: suite.id,
			isObsolete: ((suite.flags & suiteTLS12) == 0),
			randomTag:  perm[i]}
	}
	sort.Sort(ciphers)
	return ciphers.GetCiphers(), nil
}

type sortableCipher struct {
	isObsolete bool
	randomTag  int
	suite      uint16
}

type sortableCiphers []sortableCipher

func (ciphers sortableCiphers) Len() int {
	return len(ciphers)
}

func (ciphers sortableCiphers) Less(i, j int) bool {
	if ciphers[i].isObsolete && !ciphers[j].isObsolete {
		return false
	}
	if ciphers[j].isObsolete && !ciphers[i].isObsolete {
		return true
	}
	return ciphers[i].randomTag < ciphers[j].randomTag
}

func (ciphers sortableCiphers) Swap(i, j int) {
	ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
}

func (ciphers sortableCiphers) GetCiphers() []uint16 {
	cipherIDs := make([]uint16, len(ciphers))
	for i := range ciphers {
		cipherIDs[i] = ciphers[i].suite
	}
	return cipherIDs
}

// so much for generics
func shuffleTLSExtensions(s []TLSExtension) error {
	// shuffles array in place
	perm, err := getRandPerm(len(s))
	if err != nil {
		return err
	}
	for i := range s {
		s[i], s[perm[i]] = s[perm[i]], s[i]
	}
	return nil
}

// so much for generics
func shuffleSignatures(s []SignatureScheme) error {
	// shuffles array in place
	perm, err := getRandPerm(len(s))
	if err != nil {
		return err
	}
	for i := range s {
		s[i], s[perm[i]] = s[perm[i]], s[i]
	}
	return nil
}
