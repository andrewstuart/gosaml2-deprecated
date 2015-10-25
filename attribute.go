package saml

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
)

//Attributes is a custom map for unmarshalling saml attributes
type Attributes map[string]string

//UnmarshalXML implements the xml.Unmarshaler interface
func (a *Attributes) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if (*a) == nil {
		*a = make(map[string]string)
	}

	var n string

	for {
		t, err := d.Token()
		if err != nil {
			return nonEOF(err)
		}
		switch t := t.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Attribute":
				for _, attr := range t.Attr {
					if attr.Name.Local == "FriendlyName" {
						n = attr.Value
					}
				}
			}
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				fmt.Printf("t = %s\n", t)
				(*a)[n] = string(bytes.TrimSpace(t))
			}
		}
	}
}

func nonEOF(e error) error {
	if e == io.EOF {
		return nil
	}
	return e
}
