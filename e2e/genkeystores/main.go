// Command genkeystores generates JKS and PKCS12 keystore files from PEM
// certificates and a key, for use by the e2e tests of the keystore prober.
//
// It produces valid, expired and mixed (valid + expired) keystores in both
// formats so the e2e suite can exercise success, expiry and multi-certificate
// behaviour.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const password = "changeit"

func main() {
	certPath := flag.String("cert", "", "path to a PEM certificate (valid)")
	keyPath := flag.String("key", "", "path to the PEM private key for -cert")
	expiredCertPath := flag.String("expired-cert", "", "path to a PEM certificate (expired)")
	outDir := flag.String("out", ".", "output directory for the generated keystores")
	flag.Parse()

	valid := loadCertificate(*certPath)
	key := loadPrivateKey(*keyPath)
	expired := loadCertificate(*expiredCertPath)

	out := func(name string) string { return filepath.Join(*outDir, name) }

	// JKS truststores.
	writeJKS(out("keystore.jks"), map[string]*x509.Certificate{"valid": valid})
	writeJKS(out("expired.jks"), map[string]*x509.Certificate{"expired": expired})
	writeJKS(out("mixed.jks"), map[string]*x509.Certificate{"valid": valid, "expired": expired})

	// PKCS12 truststores and a keystore (private key + chain).
	writePKCS12TrustStore(out("truststore.p12"), []*x509.Certificate{valid})
	writePKCS12TrustStore(out("mixed.p12"), []*x509.Certificate{valid, expired})
	writePKCS12KeyStore(out("keystore.p12"), key, valid)

	log.Printf("generated keystores in %s", *outDir)
}

func loadCertificate(path string) *x509.Certificate {
	block := loadPEM(path)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("parse cert %s: %v", path, err)
	}
	return cert
}

func loadPrivateKey(path string) any {
	block := loadPEM(path)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("parse key %s: %v", path, err)
	}
	return key
}

func loadPEM(path string) *pem.Block {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("no PEM block in %s", path)
	}
	return block
}

func writeJKS(path string, entries map[string]*x509.Certificate) {
	ks := keystore.New()
	for alias, cert := range entries {
		if err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X509",
				Content: cert.Raw,
			},
		}); err != nil {
			log.Fatalf("set jks entry %q: %v", alias, err)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	if err := ks.Store(f, []byte(password)); err != nil {
		log.Fatalf("store jks %s: %v", path, err)
	}
}

func writePKCS12TrustStore(path string, certs []*x509.Certificate) {
	data, err := pkcs12.Modern.EncodeTrustStore(certs, password)
	if err != nil {
		log.Fatalf("encode pkcs12 truststore %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}

func writePKCS12KeyStore(path string, key any, cert *x509.Certificate) {
	data, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		log.Fatalf("encode pkcs12 keystore %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
