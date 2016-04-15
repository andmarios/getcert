/*
Command getcert downloads a certificate from a remote.
It shows some basic info and validates the certificate against
the system's CA chain as well as if it has expired or doesn't
match the remote's hostname.
It can also save the certificate to a file.
*/
package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	storeLocation string
	justCheck     bool
	help          bool
)

func init() {
	flag.StringVar(&storeLocation, "out", "", "save certificate (PEM format) to this file")
	flag.StringVar(&storeLocation, "o", "", "save certificate (PEM format) to this file —shorthand")
	flag.BoolVar(&justCheck, "just-check", false, "just check if certificate is valid for system's CA chain (exit code 2 or 3 if not)")
	flag.BoolVar(&justCheck, "c", false, "just check if certificate is valid for system's CA chain (exit code 2 or 3 if not) —shorthand")
	flag.BoolVar(&help, "help", false, "help")
	flag.BoolVar(&help, "h", false, "help")
}

var (
	validity = 0
)

const (
	validCert = iota
	otherError
	invalidExpiredCert
	wrongHostnameCert
)

func main() {
	flag.Parse()

	if help {
		PrintHelp()
		os.Exit(0)
	}

	remote := strings.Join(flag.Args(), ":")

	// Try to connect normally and detect any errors. Exit if errors are unknown.
	conn, err := tls.Dial("tcp", remote, &tls.Config{})
	if err != nil {
		if _, found := err.(x509.CertificateInvalidError); found {
			validity = invalidExpiredCert
		} else if _, found := err.(x509.HostnameError); found {
			validity = wrongHostnameCert
		} else {
			validity = otherError
			fmt.Printf("Failed to connect: " + err.Error())
			os.Exit(validity)
		}
	}

	// If we only want a verification perform it and exit as needed.
	if justCheck {
		switch validity {
		case validCert:
			fmt.Println("Certificate is valid.")
		case invalidExpiredCert:
			fmt.Println("Certificate invalid or expired.")
		case wrongHostnameCert:
			fmt.Println("Certificate doesn't match hostname.")
		}
	}

	// If we had certificate errors but we are still interested in the certificate
	// connect with relaxed settings and continue.
	if validity == invalidExpiredCert || validity == wrongHostnameCert {
		conn, err = tls.Dial("tcp", remote, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	defer conn.Close()

	// If asked to save the certificate in PEM format, do it.
	if len(storeLocation) > 0 {
		file, err := os.Create(storeLocation)
		err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: conn.ConnectionState().PeerCertificates[0].Raw})
		defer file.Close()
		if err != nil {
			fmt.Println(err)
		}
	}

	if !justCheck {
		// Print some Info
		PrintCertInfo(conn.ConnectionState().PeerCertificates[0])

		// Print Validity Info
		fmt.Println("Validity:")
		switch validity {
		case validCert:
			fmt.Println("    Valid: TRUE")
			fmt.Println("        The certificate is valid as far as your system's CA chain is concerned.")
		case invalidExpiredCert:
			fmt.Println("    Valid: FALSE")
			fmt.Println("        The certificate is either invalid or expired.")
		case wrongHostnameCert:
			fmt.Println("    Valid: FALSE")
			fmt.Println("        The certificate doesn't match the remote's hostname.")
		}
	}

	os.Exit(validity)
}

// PublicKeyAlgorithm is essentially a stringer for x509's PublicKeyAlgorith const.
func PublicKeyAlgorithm(n int) string {
	switch n {
	case 1:
		return "RSA"
	case 2:
		return "DSA"
	case 3:
		return "ECDSA"
	default:
		return "UnknownPublicKeyAlgorithm"
	}
}

// PublicKeyPrint prints info about the public key depending on its type.
// Currenty only RSA is supported.
func PublicKeyPrint(pub interface{}) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		fmt.Printf("                Public-Key: (%d bits)\n", k.N.BitLen())
		fmt.Printf("                Modulus:\n")
		key := PrettyPrintBytes(k.N.Bytes(), 16)
		for i := 0; i < len(key); i++ {
			fmt.Printf("                    %s\n", key[i])
		}
		fmt.Printf("                Exponent: %d\n", k.E)
	case *dsa.PublicKey:
		fmt.Printf("                DSA Key Information Not Implemented\n")
	case *ecdsa.PublicKey:
		fmt.Printf("                DSA Key Information Not Implemented\n")
	}
}

// PrettyPrintBytes breaks a sequence of bytes into lineLength pieces
// converts them to hex pairs, colon separated and returns them as []string.
func PrettyPrintBytes(b []byte, lineLength int) []string {
	var t [][]byte

	for i := 0; i < len(b)/lineLength; i++ {
		t = append(t, b[i*lineLength:(i+1)*lineLength-1])
	}
	if len(b)%lineLength > 0 {
		last := len(b) / lineLength
		t = append(t, b[last*lineLength:])
	}

	var s []string
	for i := 0; i < len(t); i++ {
		s = append(s, fmt.Sprintf("% X", t[i]))
		s[i] = strings.Replace(s[i], " ", ":", -1)
	}

	return s
}

// PrintCertInfo does a poor imitation of OpenSSL's `-text` output for certificates.
func PrintCertInfo(cert *x509.Certificate) {
	fmt.Printf("Certificate:\n")
	fmt.Printf("    Data:\n")
	fmt.Printf("        Version: %d\n", cert.Version)
	fmt.Printf("        Serial Number:\n")
	fmt.Printf("                % s\n", PrettyPrintBytes(cert.SerialNumber.Bytes(), 256)[0])
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("        Issuer: C=%s, O=%s, CN=%s\n", cert.Issuer.Country[0],
		cert.Issuer.Organization[0], cert.Issuer.CommonName)
	fmt.Printf("        Validity\n")
	fmt.Printf("            Not Before: %s\n", cert.NotBefore.UTC().Format(time.UnixDate))
	fmt.Printf("            Not After : %s\n", cert.NotAfter.UTC().Format(time.UnixDate))
	fmt.Printf("        Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("        Subject Public Key Info:\n")
	fmt.Printf("            Public Key Algorithm: %s\n", PublicKeyAlgorithm(int(cert.PublicKeyAlgorithm)))
	PublicKeyPrint(cert.PublicKey)
	fmt.Printf("        X509v3 extensions:\n")
	fmt.Printf("            X509v3 Key Usage: %v\n", cert.KeyUsage)
	fmt.Printf("            X509v3 Extended Key Usage: %v\n", cert.ExtKeyUsage)
	fmt.Printf("            X509v3 Basic Constraints: %v\n", cert.BasicConstraintsValid)
	fmt.Printf("            X509v3 Subject Key Identifier:\n")
	fmt.Printf("                % s\n", PrettyPrintBytes(cert.SubjectKeyId, 256)[0])
	fmt.Printf("            X509v3 Authority Key Identifier:\n")
	fmt.Printf("                % s\n", PrettyPrintBytes(cert.AuthorityKeyId, 256)[0])
	fmt.Printf("        X509v3 Subject Alternative Name:\n")
	if len(cert.DNSNames) > 0 {
		for i := 0; i < len(cert.DNSNames); i++ {
			fmt.Printf("            DNS:%s\n", cert.DNSNames[i])
		}
	}
	if len(cert.EmailAddresses) > 0 {
		for i := 0; i < len(cert.EmailAddresses); i++ {
			fmt.Printf("            Email:%s\n", cert.EmailAddresses[i])
		}
	}
	if len(cert.IPAddresses) > 0 {
		for i := 0; i < len(cert.IPAddresses); i++ {
			fmt.Printf("            DNS:%s\n", cert.IPAddresses[i])
		}
	}
	fmt.Printf("        X509v3 Certificate Policies:\n")
	if len(cert.PolicyIdentifiers) > 0 {
		for i := 0; i < len(cert.PolicyIdentifiers); i++ {
			fmt.Printf("            Policy: %v\n", cert.PolicyIdentifiers[i])
		}
	}
	fmt.Printf("        Authority Information Access:\n")
	if len(cert.OCSPServer) > 0 {
		for i := 0; i < len(cert.OCSPServer); i++ {
			fmt.Printf("            OCSP - %s\n", cert.OCSPServer[0])
		}
	}
	if len(cert.IssuingCertificateURL) > 0 {
		for i := 0; i < len(cert.IssuingCertificateURL); i++ {
			fmt.Printf("            CA Issuers - %s\n", cert.IssuingCertificateURL[0])
		}
	}
	fmt.Printf("     Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	sig := PrettyPrintBytes(cert.Signature, 18)
	for i := 0; i < len(sig); i++ {
		fmt.Printf("         %s\n", sig[i])
	}

}

func PrintHelp() {

	fmt.Println(`getcert [OPTIONS] repote port

getcert downloads a certificate from a SSL protected remote and checks it
against the system's CA chain. It prints an openssl like description and
validity information. It optionally can save the remote certificate and/or
 print minimal information.

An exit code of 2 means an invalid or expired certificate.
An exit code of 3 means a certificate that doesn't match the remote's hostname.
An exit code of 1 is a generic error, e.g inability to connect to remote.

Options:
    -o, -out FILENAME:
	    save certificate (PEM format) as FILENAME
    -c, -just-check
        just check if certificate is valid for system's CA chain (exit code 2 or
         3 if not) and do not print additional information
    -h, -help
        this text

Examples:
    Check googles SSL certificate:
        getcert www.google.com 443
    Check gmail's SMTP server certificate without printing its description:
        getcert -just-check smtp-relay.gmail.com 465
    Check example's LDAPs server certificate and save it to 'cert.pem':
        getcert -out cert.pem example.com 636
`)
}
