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

commit:

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
