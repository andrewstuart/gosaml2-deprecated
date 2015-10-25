package saml

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
)

//RelyingParty can decrypt saml
// type RelyingParty struct {
// 	cert tls.Certificate
// }

//NewRelyingParty allows a user to decrypt using a passed certificate
// func NewRelyingParty(cert tls.Certificate) (*RelyingParty, error) {
// 	rp := RelyingParty{cert}
// 	return &rp, nil
// }

//Response is an abstraction type for handling the information in a SAML
//assertion
type Response struct {
	XMLName     xml.Name
	Destination string       `xml:"Destination,attr"`
	Issuer      string       `xml:"Issuer"`
	Value       string       `xml:",attr"`
	Key         EncryptedKey `xml:"EncryptedAssertion>EncryptedData>KeyInfo>EncryptedKey"`
	Data        string       `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
	Signature   string       `xml:"Signature>SignatureValue"`
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

func (sr *Response) validateSignature(cPool []tls.Certificate) error {
	bs, err := xmlBytes(sr.Signature)
	if err != nil {
		return err
	}

	data, err := xmlBytes(sr.Data)
	if err != nil {
		return err
	}

	for _, cert := range cPool {
		err := cert.Leaf.CheckSignature(x509.SHA384WithRSA, data, bs)
		if err == nil {
			return nil
		}
	}

	return ErrNoTrustedIDP
}
