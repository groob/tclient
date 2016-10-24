package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

func TestConnect(t *testing.T) {
	server, teardown := setup(t)
	defer teardown()
	cert, err := tls.LoadX509KeyPair("testdata/server.pem", "testdata/server.key")
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	server.StartTLS()

	// connect to server
	conn, err := connect(server.URL[len("https://"):], true)
	if err != nil {
		t.Fatal(err)
	}
	have, want := len(conn.ConnectionState().PeerCertificates), len(cert.Certificate)
	if have != want {
		t.Fatalf("have %d, got %d", have, want)
	}
}

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(dump)
	})
}

func setup(t *testing.T) (server *httptest.Server, teardown func()) {
	server = httptest.NewUnstartedServer(echoHandler())
	return server, server.Close
}
