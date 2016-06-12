// pass-proxy serves as a compatibility layer for the current  version of
// pass-browser-chrome to access a password store from a folder created by the
// indexer, served by a regular webserver.
//
//     Usage of pass-proxy:
//       -socket string
//         	Proxy listen socket. (default "127.0.0.1:7277")
//       -target string
//         	Proxy target, serving the pass-indexer target directory. (default "127.0.0.1:7277")
package main // import "luit.eu/pass-server/cmd/pass-proxy"

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"strings"
)

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	socket := "127.0.0.1:7277"
	target := "127.0.0.1:80"
	fs.StringVar(&target, "socket", socket, "Proxy listen socket.")
	fs.StringVar(&target, "target", target, "Proxy target, serving the pass-indexer target directory.")

	_ = fs.Parse(os.Args[1:])

	fmt.Println(http.ListenAndServe(socket, &passProxy{
		target: target,
	}))
	os.Exit(1)
}

type passProxy struct {
	target string // target URL
}

func (p *passProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.filterBad(w, r) {
		return
	}
	body := &bytes.Buffer{}
	_, err := io.Copy(body, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = r.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/secrets") {
		p.get(w, r, "index.asc")
	} else {
		p.secret(w, r, body)
	}
}

func (p *passProxy) secret(w http.ResponseWriter, r *http.Request, body io.Reader) {
	d := json.NewDecoder(body)
	var v struct {
		Path     string `json:"path"`
		Username string `json:"username"`
	}
	err := d.Decode(&v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.get(w, r, v.Path+"/"+v.Username+".asc")
}

func (p *passProxy) get(w http.ResponseWriter, r *http.Request, secret string) {
	res, err := http.Get(p.target + secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if res.StatusCode >= 400 {
		http.Error(w, http.StatusText(res.StatusCode), res.StatusCode)
		return
	}
	if res.StatusCode != 200 {
		http.Error(w, res.Status, http.StatusBadGateway)
		return
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err = res.Body.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	v := struct {
		Response string `json:"response"`
	}{
		Response: string(body),
	}
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	_ = e.Encode(v)
}

func (p *passProxy) filterBad(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case strings.HasPrefix(r.URL.Path, "/secret/"):
	case strings.HasPrefix(r.URL.Path, "/secrets/"):
	case r.URL.Path == "/secret":
	case r.URL.Path == "/secrets":
	default:
		http.NotFound(w, r)
		return true
	}
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return true
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	if mediaType != "application/json" {
		http.Error(w, "bad content type", http.StatusBadRequest)
		return true
	}
	return false
}
