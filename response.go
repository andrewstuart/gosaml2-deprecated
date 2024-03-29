package saml

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
)

//Response is an abstraction type for handling the information in a SAML
//assertion
type Response struct {
	Destination string       `xml:"Destination,attr"`
	Issuer      string       `xml:"Issuer"`
	Value       string       `xml:",attr"`
	Key         EncryptedKey `xml:"EncryptedAssertion>EncryptedData>KeyInfo>EncryptedKey"`
	Data        string       `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
	Signature   string       `xml:"Signature>SignatureValue"`
	Digest      string       `xml:"Signature>SignedInfo>Reference>DigestValue"`
	Signed      []byte
	//TODO xml.Unmarshaler to automatically decrypt assertion?
	// Assertion   Assertion    `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
}

//TODO replace NewResponseFromReader with a custom UnmrashalXML?

//NewResponseFromReader returns a Response or error based on the given reader.
func NewResponseFromReader(r io.Reader) (*Response, error) {
	buf := &bytes.Buffer{}

	var res Response

	//Decode and copy bytes into buffer
	err := xml.NewDecoder(io.TeeReader(r, buf)).Decode(&res)
	if err != nil {
		return nil, err
	}

	//RE to remove enveloped signature
	re := regexp.MustCompile("(?sm)ds:Signature.*</ds:Signature>.*?<")

	//Copy raw bytes into response for use in verifying signature
	res.Signed = re.ReplaceAll(buf.Bytes(), nil)

	return &res, nil
}

//Decrypt returns the byte slice contained in the encrypted data.
func (sr *Response) Decrypt(cert tls.Certificate) ([]byte, error) {

	data, err := xmlBytes(sr.Data)
	if err != nil {
		return nil, err
	}

	k, err := sr.Key.SymmetricKey(cert)

	if err != nil {
		return nil, fmt.Errorf("cannot decrypt, error retrieving private key: %v", err)
	}

	plainText := make([]byte, len(data))

	//Get CBC decrypter using IV
	c := cipher.NewCBCDecrypter(k, data[:aes.BlockSize])

	//Decrypt blocks
	c.CryptBlocks(plainText, data[aes.BlockSize:])

	//Remove zero block if needed
	plainText = bytes.TrimRight(plainText, string([]byte{0}))

	//Calculate index tot remove based on padding
	padLength := plainText[len(plainText)-1]
	lastGoodIndex := len(plainText) - int(padLength)

	return plainText[:lastGoodIndex], nil
}
