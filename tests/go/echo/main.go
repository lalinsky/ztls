// A TLS 1.3 echo peer on Go's crypto/tls, for ztls's interoperability
// tests: Go has X25519MLKEM768 on by default, which OpenSSL before 3.5
// does not.
//
// Server mode listens, prints "READY <address>", serves one connection
// (echoing each line as "echo: <line>") and exits. Client mode connects,
// copies stdin to the connection and the connection to stdout, and sends
// close_notify when stdin ends.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func main() {
	listen := flag.String("listen", "", "serve on this address")
	connect := flag.String("connect", "", "connect to this address")
	cert := flag.String("cert", "", "certificate chain PEM")
	key := flag.String("key", "", "private key PEM")
	ca := flag.String("ca", "", "trusted CA PEM, for verifying the peer")
	alpn := flag.String("alpn", "", "comma-separated ALPN protocols")
	serverName := flag.String("servername", "localhost", "server name to send and verify")
	requireClientCert := flag.Bool("require-client-cert", false, "server: require a client certificate")
	tls12 := flag.Bool("tls12", false, "speak TLS 1.2 instead of 1.3")
	flag.Parse()

	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: *serverName}
	if *tls12 {
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12
	}
	if *alpn != "" {
		cfg.NextProtos = strings.Split(*alpn, ",")
	}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		cfg.RootCAs = pool
		cfg.ClientCAs = pool
	}
	if *cert != "" {
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	if *requireClientCert {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	if *listen != "" {
		ln, err := tls.Listen("tcp", *listen, cfg)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("READY %s\n", ln.Addr())
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		tconn := conn.(*tls.Conn)
		if err := tconn.Handshake(); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("ALPN %s\n", tconn.ConnectionState().NegotiatedProtocol)
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			if _, err := fmt.Fprintf(conn, "echo: %s\n", scanner.Text()); err != nil {
				log.Fatal(err)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
		conn.Close()
		return
	}

	conn, err := tls.Dial("tcp", *connect, cfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ALPN %s\n", conn.ConnectionState().NegotiatedProtocol)
	go func() {
		io.Copy(conn, os.Stdin)
		conn.CloseWrite()
	}()
	io.Copy(os.Stdout, conn)
	conn.Close()
}
