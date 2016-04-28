package saml

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var testContext = Context{
	Audience: "oauth.astuart.co",
}

func init() {
	bs, err := ioutil.ReadFile("./testdata/idp.crt")
	if err != nil {
		log.Fatal("bad signing cert", err)
	}

	block, _ := pem.Decode(bs)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	testContext.IDPCerts = []tls.Certificate{{Leaf: cert}}
}

func TestAssertion(t *testing.T) {
	f, err := os.Open("./testdata/assertion.xml")
	if err != nil {
		t.Fatalf("could not open saml assertion test file: %v\n", err)
	}

	var a Assertion
	err = xml.NewDecoder(f).Decode(&a)
	if err != nil {
		t.Fatalf("error decoding xml: %v\n", err)
	}

	if len(a.Conditions.List) < 1 {
		t.Fatalf("conditions not unmashalled. length is %d, should be at least 1", len(a.Conditions.List))
	}

	// if a.Conditions.List[0].Validate(Context{Audience: "oauth.astuart.co"}) != nil {
	// 	t.Errorf("did not validate audience")
	// }

	fmt.Printf("a = %+v\n", a.Attributes)
}
