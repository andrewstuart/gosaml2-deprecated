package saml

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
)

//BString is a convenience unmarshaller for base64 to bytes
type BString []byte

//UnmarshalXML implements the Unmarshaler interface
func (b *BString) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string

	err := d.DecodeElement(&s, &start)
	if err != nil {
		return err
	}

	bs, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))

	if err != nil {
		return err
	}

	*b = bs

	return nil
}
