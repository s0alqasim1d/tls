// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "fmt"

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

	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

type ClientHelloID struct {
	Browser string
	Version uint16
	// TODO: consider adding OS?
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%d", p.Browser, p.Version)
}

const (
	helloGolang     = "Golang"
	helloRandomized = "Randomized"
	helloCustom     = "Custom"
	helloFirefox    = "Firefox"
	helloChrome     = "Chrome"
	helloAndroid    = "Android"
)

const (
	helloAutoVers = iota
	helloRandomizedALPN
	helloRandomizedNoALPN
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

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang = ClientHelloID{helloGolang, helloAutoVers}

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	HelloCustom = ClientHelloID{helloCustom, helloAutoVers}

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       = ClientHelloID{helloRandomized, helloAutoVers}
	HelloRandomizedALPN   = ClientHelloID{helloRandomized, helloRandomizedALPN}
	HelloRandomizedNoALPN = ClientHelloID{helloRandomized, helloRandomizedNoALPN}

	// The rest will will parrot given browser.
	HelloFirefox_Auto = HelloFirefox_56
	HelloFirefox_55   = ClientHelloID{helloFirefox, 55}
	HelloFirefox_56   = ClientHelloID{helloFirefox, 56}

	HelloChrome_Auto = HelloChrome_62
	HelloChrome_58   = ClientHelloID{helloChrome, 58}
	HelloChrome_62   = ClientHelloID{helloChrome, 62}
)

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
const GREASE_PLACEHOLDER = 0x0a0a
