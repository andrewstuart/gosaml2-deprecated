package saml

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var cert tls.Certificate
var pk crypto.PrivateKey

func init() {
	var err error
	pfx := "../openid-sp-enc"
	cert, err = tls.LoadX509KeyPair(fmt.Sprintf("%s.crt", pfx), fmt.Sprintf("%s.key", pfx))
	if err != nil {
		log.Fatal(err)
	}
	pk = cert.PrivateKey
}

func TestDecode(t *testing.T) {
	f, err := os.Open("./testdata/saml.xml")
	if err != nil {
		t.Fatalf("could not open test file: %v\n", err)
	}
	defer f.Close()

	var r Response
	err = xml.NewDecoder(f).Decode(&r)
	if err != nil {
		t.Fatalf("error decoding test saml: %v", err)
	}

	k, err := r.Key.SymmetricKey(cert)
	if err != nil {
		t.Fatalf("could not get symmetric key: %v\n", err)
	}

	if k == nil {
		t.Fatalf("no symmetric key")
	}

	bs, err := r.Decrypt(cert)
	if err != nil {
		t.Fatalf("error decrypting saml data: %v\n", err)
	}

	bs = bytes.TrimSpace(bs)

	if len(bs) == 0 {
		t.Fatalf("decrypt returned no bytes")
	}

	bs, err = ioutil.ReadFile("./testdata/saml.xml")
	if err != nil {
		t.Fatalf("load: %v\n", err)
	}

	r.Raw = bs

	err = r.validateSignature(testContext.IDPCerts)

	if err != nil {
		t.Errorf("signature verification failure: %v", err)
	}

}
