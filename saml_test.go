package saml

import (
	"encoding/xml"
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

	bs, err := r.Decrypt()
	if err != nil {
		t.Fatalf("error decrypting saml data: %v\n", err)
	}

	t.Log(string(bs))
}
