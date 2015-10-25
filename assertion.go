package saml

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

//Errors that may be encountered while validating an assertion
var (
	ErrTooSoon          = fmt.Errorf("assertion not valid yet")
	ErrTooLate          = fmt.Errorf("assertion no longer valid")
	ErrAudienceMismatch = fmt.Errorf("audience mismatch")
)

//Assertion is a type to deserialize SAML assertions
type Assertion struct {
	ID           string    `xml:"ID,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Version      string    `xml:"Version,attr"`
	Issuer       string
	NameID       BString `xml:"Subject>NameID"`
	Conditions   Conditions
	Attributes   Attributes `xml:"AttributeStatement"`
}

//Validate takes a Context and returns an error. Nil return means a successful
//validation
func (a *Assertion) Validate(c Context) error {
	//TODO validate signature

	//Check the assertion condition time range
	n := time.Now()
	if n.Before(a.Conditions.NotBefore) {
		return ErrTooSoon
	}
	if n.Equal(a.Conditions.ToNotOnOrAfter) || n.After(a.Conditions.ToNotOnOrAfter) {
		return ErrTooLate
	}

	//Check the list of conditions
	for i := range a.Conditions.List {
		err := a.Conditions.List[i].Validate(c)
		if err != nil {
			return err
		}
	}

	//Valid
	return nil
}

//Conditions holds a list of the contingencies of a SAMl assertion
type Conditions struct {
	NotBefore      time.Time `xml:"NotBefore,attr"`
	ToNotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
	List           []Condition
}

//UnmarshalXML implements the Unmarshaler interface
func (cs *Conditions) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		var err error
		switch attr.Name.Local {
		case "NotBefore":
			cs.NotBefore, err = time.Parse(time.RFC3339, attr.Value)
		case "NotOnOrAfter":
			cs.ToNotOnOrAfter, err = time.Parse(time.RFC3339, attr.Value)
		}
		if err != nil {
			return err
		}
	}

	for {
		t, err := d.Token()

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch t := t.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "AudienceRestriction":
				var ar AudienceRestriction

				err := d.DecodeElement(&ar, &t)
				if err != nil {
					return err
				}
				cs.List = append(cs.List, &ar)
			}
		}
	}
}

//Context is an encapsulation of server state that can be inspected by
//Conditions
type Context struct {
	Audience string
	IDPCerts []tls.Certificate
}

//The Condition interface validates a context based on the condition's internal
//state
type Condition interface {
	Validate(c Context) error
}

//AudienceRestriction is a condition on the audience of the server, or the
//intended recipient of the SAML assertion
type AudienceRestriction struct {
	XMLName  xml.Name `xml:"AudienceRestriction"`
	Audience string
}

//Validate implements the Condition interface
func (ar *AudienceRestriction) Validate(c Context) error {
	if strings.TrimSpace(ar.Audience) == strings.TrimSpace(c.Audience) {
		return nil
	}
	return ErrAudienceMismatch
}
