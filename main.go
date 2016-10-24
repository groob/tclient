package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

var version = "unknown"
var gitHash = "unknown"

func main() {
	var (
		flVersion = flag.Bool("version", false, "print version information")
		insecure  = flag.Bool("insecure", false, "do not verify tls certs")
		info      = flag.Bool("info", false, "print subject and issuer info for each certificate in the chain")
		server    = flag.String("server", "", "server and port to connect to: Example: github.com:443")
	)
	flag.Parse()

	if *flVersion {
		fmt.Printf("tclient - %v\n", version)
		fmt.Printf("git revision - %v\n", gitHash)
		os.Exit(0)
	}
	if *server == "" {
		log.Fatal("must specify server url and port. Example: github.com:443")
	}

	conn, err := connect(*server, *insecure)
	if err != nil {
		log.Fatalf("failed to establish connection: %s\n", err)
	}

	pemChain, err := chain(conn.ConnectionState(), *info)
	if err != nil {
		log.Fatalf("failed to parse full chain: %s\n", err)
	}
	fmt.Println(string(pemChain))

	hasRoot, issuer := hasRootCA(conn.ConnectionState())
	if !hasRoot {
		fmt.Fprintf(os.Stderr, "[WARNING] Root CA cert missing from response. Issuer: %s\n", issuer)
	}
}

// connect uses tls.Dial to establish a connection
func connect(serverURL string, insecure bool) (*tls.Conn, error) {
	conn, err := tls.Dial("tcp", serverURL, &tls.Config{InsecureSkipVerify: insecure})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn, nil
}

// hasRootCA verifies that the last cert in the chain is a Root CA.
// This test appears to work although it's a bit dubious.
func hasRootCA(cs tls.ConnectionState) (bool, string) {
	var topCert *x509.Certificate
	if len(cs.VerifiedChains) != 0 {
		for _, chain := range cs.VerifiedChains {
			for _, cert := range chain {
				topCert = cert
			}
		}
	} else {
		for _, cert := range cs.PeerCertificates {
			topCert = cert
		}
	}
	return topCert.Issuer.CommonName == topCert.Subject.CommonName, topCert.Issuer.CommonName
}

// chain builds a PEM encoded certificate chain
func chain(cs tls.ConnectionState, addInfo bool) ([]byte, error) {
	buf := bytes.NewBuffer([]byte(""))
	if len(cs.VerifiedChains) != 0 {
		for _, chain := range cs.VerifiedChains {
			for i, cert := range chain {
				if addInfo {
					addCertInfo(buf, i, cert)
				}
				if err := encodePEM(buf, cert); err != nil {
					return nil, err
				}
			}
		}
	} else {
		for i, cert := range cs.PeerCertificates {
			if addInfo {
				addCertInfo(buf, i, cert)
			}
			if err := encodePEM(buf, cert); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

/*
 1 s:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert SHA2 Extended Validation Server CA
   i:/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
*/
func addCertInfo(buf *bytes.Buffer, num int, cert *x509.Certificate) {
	// subject
	buf.WriteString(fmt.Sprintf("%d s:", num))
	if len(cert.Subject.Country) != 0 {
		buf.WriteString(fmt.Sprintf("/C=%s", cert.Subject.Country[0]))
	}
	if len(cert.Subject.Organization) != 0 {
		buf.WriteString(fmt.Sprintf("/O=%s", cert.Subject.Organization[0]))
	}
	if len(cert.Subject.OrganizationalUnit) != 0 {
		buf.WriteString(fmt.Sprintf("/OU=%s", cert.Subject.OrganizationalUnit[0]))
	}
	buf.WriteString(fmt.Sprintf("/CN=%s", cert.Subject.CommonName))
	buf.WriteString("\n")

	// issuer
	buf.WriteString("  i:")
	if len(cert.Issuer.Country) != 0 {
		buf.WriteString(fmt.Sprintf("/C=%s", cert.Issuer.Country[0]))
	}
	if len(cert.Issuer.Organization) != 0 {
		buf.WriteString(fmt.Sprintf("/O=%s", cert.Issuer.Organization[0]))
	}
	if len(cert.Issuer.OrganizationalUnit) != 0 {
		buf.WriteString(fmt.Sprintf("/OU=%s", cert.Issuer.OrganizationalUnit[0]))
	}
	buf.WriteString(fmt.Sprintf("/CN=%s", cert.Issuer.CommonName))
	buf.WriteString("\n")

}

func encodePEM(buf io.Writer, cert *x509.Certificate) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.Encode(buf, block)
}
