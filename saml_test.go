package saml

import (
	"bytes"
	"encoding/xml"
	"log"
	"os"
	"testing"
)

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

	k, err := r.Key.SymmetricKey()
	if err != nil {
		t.Fatalf("could not get symmetric key: %v\n", err)
	}

	if k == nil {
		t.Fatalf("no symmetric key")
	}

	bs, err := r.Decrypt()
	if err != nil {
		t.Fatalf("error decrypting saml data: %v\n", err)
	}

	bs = bytes.TrimSpace(bs)

	if len(bs) == 0 {
		t.Fatalf("decrypt returned no bytes")
	}

	log.Println(string(bs[16:]))
}
