package saml

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/lestrrat/go-libxml2"
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
	Raw         []byte       //       `xml:",innerxml"`
	//TODO xml.Unmarshaler to automatically decrypt assertion?
	// Assertion   Assertion    `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
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

func (sr *Response) validateSignature(trusted []tls.Certificate) error {
	sig, err := xmlBytes(sr.Digest)
	if err != nil {
		return err
	}

	// re := regexp.MustCompile("(?sm)ds:Signature.*</ds:Signature>.*?<")

	p := &libxml2.Parser{}
	doc, err := p.Parse(bytes.NewBuffer(sr.Raw))
	if err != nil {
		return err
	}

	canon, err := doc.ToStringC14N(true)
	if err != nil {
		return err
	}

	for _, cert := range trusted {
		err = cert.Leaf.CheckSignature(x509.SHA256WithRSA, []byte(canon), sig)
		if err == nil {
			return nil
		}
		log.Println(err)
	}

	return ErrNoTrustedIDP
}
