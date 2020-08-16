package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

/*
SSL certificates

X.509 is an ITU-T (International Telecommunication Union Telecommunication Standardization
Sector) standard for a Public Key Infrastructure (PKI). X.509 includes
standard formats for public key certificates.
An X.509 certificate (also colloquially called an SSL certificate) is a digital document
expressed in ASN.1 (Abstract Syntax Notation One) that has been encoded. ASN.1 is
a standard and notation that describes rules and structures for representing data in
telecommunications and computer networking.
X.509 certificates can be encoded in various formats, including BER (Basic Encoding
Rules). The BER format specifies a self-describing and self-delimiting format for
encoding ASN.1 data structures. DER is a subset of BER, providing for exactly one
way to encode an ASN.1 value, and is widely used in cryptography, especially X.509
certificates.
In SSL, the certificates can be saved in files of different formats. One of them is PEM
(Privacy Enhanced Email, which doesn’t have much relevance here except as the name
of the file format used), which is a Base64-encoded DER X.509 certificate enclosed
between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----".
*/
func main() {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)
	subject := pkix.Name{
		Organization:       []string{"FEARLESS SPIDER"},
		OrganizationalUnit: []string{"IT"},
		CommonName:         "Go Web Programming",
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
	certOut, _ := os.Create("cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	keyOut, _ := os.Create("key.pem")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	keyOut.Close()
}
