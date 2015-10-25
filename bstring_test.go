package saml

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

func TestBString(t *testing.T) {
	x := strings.NewReader("<ele>aGVsbG8gd29ybGQ=</ele>")

	var bt BString
	err := xml.NewDecoder(x).Decode(&bt)
	if err != nil {
		t.Fatalf("error decoding text xml: %v\n", err)
	}

	cmp := []byte("hello world")

	if !bytes.Equal(bt, cmp) {
		t.Errorf("Wrong base64 string: %s, should be %s", bt, cmp)
	}
}
