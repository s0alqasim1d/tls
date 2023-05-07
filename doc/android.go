package main

import (
	"2a.pages.dev/tls"
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var android_API_26 = tls.ClientHelloSpec{
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	Extensions: []tls.TLSExtension{
		&tls.RenegotiationInfoExtension{},
		&tls.SNIExtension{},
		&tls.UtlsExtendedMasterSecretExtension{},
		&tls.SessionTicketExtension{},
		&tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
			},
		},
		&tls.StatusRequestExtension{},
		&tls.ALPNExtension{
			AlpnProtocols: []string{"http/1.1"},
		},
		&tls.SupportedPointsExtension{
			SupportedPoints: []uint8{tls.PointFormatUncompressed},
		},
		&tls.SupportedCurvesExtension{
			Curves: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
	},
}

func main() {
	conf := tls.Config{ServerName: "android.googleapis.com"}
	dial_conn, err := net.Dial("tcp", "android.googleapis.com:443")
	if err != nil {
		panic(err)
	}
	tls_conn := tls.UClient(dial_conn, &conf, tls.HelloCustom)
	defer tls_conn.Close()
	if err := tls_conn.ApplyPreset(&android_API_26); err != nil {
		panic(err)
	}
	body := url.Values{
		"Email":              {email},
		"Passwd":             {passwd},
		"client_sig":         {""},
		"droidguard_results": {"-"},
	}.Encode()
	req, err := http.NewRequest(
		"POST", "https://android.googleapis.com/auth",
		strings.NewReader(body),
	)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	if err := req.Write(tls_conn); err != nil {
		panic(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(tls_conn), req)
	if err != nil {
		panic(err)
	}
	if err := res.Body.Close(); err != nil {
		panic(err)
	}
	fmt.Println(res.Status)
}
