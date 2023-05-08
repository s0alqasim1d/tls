// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/binary"
	"errors"
	"io"
	"strconv"
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

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Things, supported by utls, but not crypto/tls' are prefixed with "utls"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.
const (
	utlsExtensionPadding              uint16 = 21
	utlsExtensionExtendedMasterSecret uint16 = 23 // https://tools.ietf.org/html/rfc7627

	// extensions with 'fake' prefix break connection, if server echoes them back
	fakeExtensionChannelID uint16 = 30032 // not IANA assigned
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5          = uint16(0x0004)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = uint16(0x00ff)
)

// newest signatures
var (
	FakePKCS1WithSHA224 SignatureScheme = 0x0301
	FakeECDSAWithSHA224 SignatureScheme = 0x0303
)

type ClientHelloSpec struct {
	CipherSuites       []uint16       // nil => default
	CompressionMethods []uint8        // nil => no compression
	Extensions         []TLSExtension // nil => no extensions

	// GreaseStyle: currently only random

	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

var Android_API_26 = ClientHelloSpec{
	CipherSuites: []uint16{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	Extensions: []TLSExtension{
		&RenegotiationInfoExtension{},
		&SNIExtension{},
		&UtlsExtendedMasterSecretExtension{},
		&SessionTicketExtension{},
		&SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
			},
		},
		&StatusRequestExtension{},
		&ALPNExtension{
			AlpnProtocols: []string{"http/1.1"},
		},
		&SupportedPointsExtension{
			SupportedPoints: []uint8{PointFormatUncompressed},
		},
		&SupportedCurvesExtension{
			Curves: []CurveID{
				X25519,
				CurveP256,
				CurveP384,
			},
		},
	},
}

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
const GREASE_PLACEHOLDER = 0x0a0a
