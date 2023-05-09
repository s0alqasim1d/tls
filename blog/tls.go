package main

import (
   "2a.pages.dev/tls"
   "bufio"
   "fmt"
   "net"
   "net/http"
   "net/url"
   "strings"
   "testing"
)

func main() {
   conf := tls.Config{ServerName: "android.googleapis.com"}
   dial_conn, err := net.Dial("tcp", "android.googleapis.com:443")
   if err != nil {
      panic(err)
   }
   tls_conn := tls.UClient(dial_conn, &conf)
   defer tls_conn.Close()
   if err := tls_conn.ApplyPreset(&tls.Android_API_26); err != nil {
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
