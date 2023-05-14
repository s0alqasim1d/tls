package tls

import (
   "bufio"
   "fmt"
   "net"
   "net/http"
   "net/url"
   "os"
   "strings"
   "testing"
)

func user_info(name string) ([]string, error) {
   data, err := os.ReadFile(name)
   if err != nil {
      return nil, err
   }
   return strings.Split(string(data), "\n"), nil
}

func Test_TLS(t *testing.T) {
   home, err := os.UserHomeDir()
   if err != nil {
      t.Fatal(err)
   }
   user, err := user_info(home + "/Documents/gmail.txt")
   if err != nil {
      t.Fatal(err)
   }
   conf := Config{ServerName: "android.googleapis.com"}
   dial_conn, err := net.Dial("tcp", "android.googleapis.com:443")
   if err != nil {
      t.Fatal(err)
   }
   tls_conn := UClient(dial_conn, &conf)
   defer tls_conn.Close()
   if err := tls_conn.ApplyPreset(&Android_API_26); err != nil {
      t.Fatal(err)
   }
   body := url.Values{
      "Email":              {user[0]},
      "Passwd":             {user[1]},
      "client_sig":         {""},
      "droidguard_results": {"-"},
   }.Encode()
   req, err := http.NewRequest(
      "POST", "https://android.googleapis.com/auth",
      strings.NewReader(body),
   )
   if err != nil {
      t.Fatal(err)
   }
   req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
   req.Proto = "HTTP/1.1"
   req.ProtoMajor = 1
   req.ProtoMinor = 1
   if err := req.Write(tls_conn); err != nil {
      t.Fatal(err)
   }
   res, err := http.ReadResponse(bufio.NewReader(tls_conn), req)
   if err != nil {
      t.Fatal(err)
   }
   if err := res.Body.Close(); err != nil {
      t.Fatal(err)
   }
   fmt.Println(res.Status)
}
