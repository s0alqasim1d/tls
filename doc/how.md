# how

size:

- https://api.github.com/repos/4cq2/tls
- https://docs.github.com/search-github/searching-on-github/searching-for-repositories

enable flexible external configuration:

https://github.com/refraction-networking/utls/tree/112951f6

before the first commit, lets remove large items:

~~~
handshake_client_test.go
handshake_server_test.go
testdata
~~~

now create `go.mod`:

~~~
go mod init 2a.pages.dev/tls
~~~

create `go.sum`:

~~~
go mod tidy
~~~

then export:

~~~
gofmt -w -r 'pointFormatUncompressed -> PointFormatUncompressed' .
~~~

renegotiation and export extension fields:

https://github.com/refraction-networking/utls/commit/1552a980

remove:

~~~
.travis.yml
CONTRIBUTING.md
CONTRIBUTORS_GUIDE.md
cpu
example_test.go
generate_cert.go
handshake_messages_test.go
examples
handshake_test.go
prf_test.go
testenv
tls_test.go
conn_test.go
u_conn_test.go
~~~

then:

~~~diff
+++ b/common.go
@@ -21,2 +20,0 @@ import (
-
-       "github.com/refraction-networking/utls/cpu"
~~~

error:

~~~
common.go:923:20: undefined: cpu
~~~

fix:

~~~diff
+++ b/common.go
@@ -919,40 +919,9 @@ func initDefaultCipherSuites() {
-       var topCipherSuites []uint16
-
-       // Check the cpu flags for each platform that has optimized GCM implementations.
-       // Worst case, these variables will just all be false
-       hasGCMAsmAMD64 := cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
-
-       // TODO: enable the arm64 HasAES && HasPMULL feature check after the
-       // optimized AES-GCM implementation for arm64 is merged (CL 107298).
-       // This is explicitly set to false for now to prevent misprioritization
-       // of AES-GCM based cipher suites, which will be slower than chacha20-poly1305
-       hasGCMAsmARM64 := false
-       // hasGCMAsmARM64 := cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
-
-       // Keep in sync with crypto/aes/cipher_s390x.go.
-       hasGCMAsmS390X := false // [UTLS: couldn't be bothered to make it work, we won't use it]
-
-       hasGCMAsm := hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
-
-       if hasGCMAsm {
-               // If AES-GCM hardware is provided then prioritise AES-GCM
-               // cipher suites.
-               topCipherSuites = []uint16{
-                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
-               }
-       } else {
-               // Without AES-GCM hardware, we put the ChaCha20-Poly1305
-               // cipher suites first.
-               topCipherSuites = []uint16{
-                       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
-               }
+       // Without AES-GCM hardware, we put the ChaCha20-Poly1305 cipher suites
+       // first.
+       topCipherSuites := []uint16{
+               TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
+               TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
+               TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
+               TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
+               TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
+               TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
~~~

fix:

~~~diff
+++ b/cipher_suites.go
@@ -17,2 +16,0 @@ import (
-
-       "golang.org/x/crypto/chacha20poly1305"
~~~

error:

~~~
cipher_suites.go:232:15: undefined: chacha20poly1305
~~~

fix:

~~~diff
@@ -231,11 +230,0 @@ func aeadAESGCM(key, fixedNonce []byte) cipher.AEAD {
-func aeadChaCha20Poly1305(key, fixedNonce []byte) cipher.AEAD {
-       aead, err := chacha20poly1305.New(key)
-       if err != nil {
-               panic(err)
-       }
-
-       ret := &xorNonceAEAD{aead: aead}
-       copy(ret.nonceMask[:], fixedNonce)
-       return ret
-}
-
~~~

errors:

~~~
cipher_suites.go:79:99: undefined: aeadChaCha20Poly1305
cipher_suites.go:80:116: undefined: aeadChaCha20Poly1305
~~~

fix:

~~~diff
-{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
-{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheECDSAKA, suiteECDHE | suiteECDSA | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
~~~

error:

~~~
u_common.go:131:57: undefined: aeadChaCha20Poly1305
u_common.go:133:70: undefined: aeadChaCha20Poly1305
~~~

fix:

~~~diff
@@ -124,2 +123,0 @@ func utlsMacSHA384(version uint16, key []byte) macFunction {
-var utlsSupportedCipherSuites []*cipherSuite
-
@@ -129,7 +126,0 @@ func init() {
-       utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
-               {OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
-                       suiteECDHE | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
-               {OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
-                       suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
-       }...)
-
~~~

error:

~~~
u_common.go:136:2: undefined: utlsSupportedCipherSuites
~~~

fix:

~~~diff
@@ -130,16 +129,0 @@ func init() {
-
-// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
-// This provides better compatibility with servers on the web, but weakens security. Feel free
-// to use this option if you establish additional secure connection inside of utls connection.
-// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
-func EnableWeakCiphers() {
-       utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
-               {DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
-                       suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},
-
-               {DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
-                       suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
-               {DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
-                       suiteECDHE | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
-       }...)
-}
~~~

error:

~~~
cipher_suites.go:338:26: undefined: utlsSupportedCipherSuites
~~~

fix:

~~~diff
-for _, suite := range utlsSupportedCipherSuites { // [UTLS]
+for _, suite := range cipherSuites {
~~~

commit:

https://github.com/golang/go/commit/4caa1276

commit:

https://github.com/golang/go/commit/d88d91e3

commit:

https://github.com/golang/go/commit/dafc9152

remove:

~~~
cipher_suites.go:181:6: type xorNonceAEAD is unused (U1000)
cipher_suites.go:186:24: func (*xorNonceAEAD).NonceSize is unused (U1000)
cipher_suites.go:187:24: func (*xorNonceAEAD).Overhead is unused (U1000)
cipher_suites.go:188:24: func (*xorNonceAEAD).explicitNonceLen is unused (U1000)
cipher_suites.go:190:24: func (*xorNonceAEAD).Seal is unused (U1000)
cipher_suites.go:202:24: func (*xorNonceAEAD).Open is unused (U1000)
handshake_messages.go:34:26: func (*clientHelloMsg).equal is unused (U1000)
handshake_messages.go:525:26: func (*serverHelloMsg).equal is unused (U1000)
handshake_messages.go:851:26: func (*certificateMsg).equal is unused (U1000)

handshake_messages.go:938:32: func (*serverKeyExchangeMsg).equal is unused (U1000)
handshake_messages.go:979:32: func (*certificateStatusMsg).equal is unused (U1000)
handshake_messages.go:1041:30: func (*serverHelloDoneMsg).equal is unused (U1000)
handshake_messages.go:1061:32: func (*clientKeyExchangeMsg).equal is unused (U1000)
handshake_messages.go:1105:23: func (*finishedMsg).equal is unused (U1000)
handshake_messages.go:1142:24: func (*nextProtoMsg).equal is unused (U1000)
handshake_messages.go:1219:33: func (*certificateRequestMsg).equal is unused (U1000)
handshake_messages.go:1369:32: func (*certificateVerifyMsg).equal is unused (U1000)
handshake_messages.go:1449:31: func (*newSessionTicketMsg).equal is unused (U1000)
handshake_messages.go:1514:6: func eqUint16s is unused (U1000)
handshake_messages.go:1526:6: func eqCurveIDs is unused (U1000)
handshake_messages.go:1538:6: func eqStrings is unused (U1000)
handshake_messages.go:1550:6: func eqByteSlices is unused (U1000)
handshake_messages.go:1562:6: func eqSignatureAlgorithms is unused (U1000)
ticket.go:101:24: func (*sessionState).equal is unused (U1000)
u_common.go:120:6: func utlsMacSHA384 is unused (U1000)
~~~
