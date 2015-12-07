# saml
--
    import "github.com/andrewstuart/gosaml2"

Package saml is intended to provide decryption and verification of
SAML-compliant documents. It is currently incomplete although it can do
decryption (but not authentication) of SAML2 assertions, provided that encrypt
the assertion with an AES256 key which is RSA encrypted for the host.

## Usage

```go
var (
	ErrTooSoon          = fmt.Errorf("assertion not valid yet")
	ErrTooLate          = fmt.Errorf("assertion no longer valid")
	ErrAudienceMismatch = fmt.Errorf("audience mismatch")
	ErrNoTrustedIDP     = fmt.Errorf("failed to find a trusted idp certificate")
)
```
Errors that may be encountered while validating an assertion

#### type Assertion

```go
type Assertion struct {
	ID           string    `xml:"ID,attr"`
	IssueInstant time.Time `xml:"IssueInstant,attr"`
	Version      string    `xml:"Version,attr"`
	Issuer       string
	NameID       BString `xml:"Subject>NameID"`
	Conditions   Conditions
	Attributes   Attributes `xml:"AttributeStatement"`
}
```

Assertion is a type to deserialize SAML assertions

#### func (*Assertion) Validate

```go
func (a *Assertion) Validate(c Context) error
```
Validate takes a Context and returns an error. Nil return means a successful
validation

#### type Attributes

```go
type Attributes map[string]string
```

Attributes is a custom map for unmarshalling saml attributes

#### func (*Attributes) UnmarshalXML

```go
func (a *Attributes) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error
```
UnmarshalXML implements the xml.Unmarshaler interface

#### type AudienceRestriction

```go
type AudienceRestriction struct {
	XMLName  xml.Name `xml:"AudienceRestriction"`
	Audience string
}
```

AudienceRestriction is a condition on the audience of the server, or the
intended recipient of the SAML assertion

#### func (*AudienceRestriction) Validate

```go
func (ar *AudienceRestriction) Validate(c Context) error
```
Validate implements the Condition interface

#### type BString

```go
type BString []byte
```

BString is a convenience unmarshaller for base64 to bytes

#### func (*BString) UnmarshalXML

```go
func (b *BString) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error
```
UnmarshalXML implements the Unmarshaler interface

#### type Condition

```go
type Condition interface {
	Validate(c Context) error
}
```

The Condition interface validates a context based on the condition's internal
state

#### type Conditions

```go
type Conditions struct {
	NotBefore    time.Time `xml:"NotBefore,attr"`
	NotOnOrAfter time.Time `xml:"NotOnOrAfter,attr"`
	List         []Condition
}
```

Conditions holds a list of the contingencies of a SAMl assertion

#### func (*Conditions) UnmarshalXML

```go
func (cs *Conditions) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error
```
UnmarshalXML implements the Unmarshaler interface

#### type Context

```go
type Context struct {
	Audience string
	IDPCerts []tls.Certificate
}
```

Context is an encapsulation of server state that can be inspected by Conditions

#### type EncryptedKey

```go
type EncryptedKey struct {
	// EncryptionMethod string `xml:"EncryptionMethod>Algorithm"`
	X509Data    string `xml:"KeyInfo>X509Data>X509Certificate"`
	CipherValue string `xml:"CipherData>CipherValue"`
}
```

EncryptedKey contains the decryption key data from the saml2 core and xmlenc
standards.

#### func (*EncryptedKey) SymmetricKey

```go
func (ek *EncryptedKey) SymmetricKey(cert tls.Certificate) (cipher.Block, error)
```
SymmetricKey returns the private key contained in the EncryptedKey document

#### type Response

```go
type Response struct {
	Destination string       `xml:"Destination,attr"`
	Issuer      string       `xml:"Issuer"`
	Value       string       `xml:",attr"`
	Key         EncryptedKey `xml:"EncryptedAssertion>EncryptedData>KeyInfo>EncryptedKey"`
	Data        string       `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
	Signature   string       `xml:"Signature>SignatureValue"`
	Digest      string       `xml:"Signature>SignedInfo>Reference>DigestValue"`
	Raw         []byte       //       `xml:",innerxml"`

}
```

Response is an abstraction type for handling the information in a SAML assertion

#### func (*Response) Decrypt

```go
func (sr *Response) Decrypt(cert tls.Certificate) ([]byte, error)
```
Decrypt returns the byte slice contained in the encrypted data.
