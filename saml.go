package saml

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
)

//EncryptedKey contains the decryption key data from the saml2 core and xmlenc
//standards.
type EncryptedKey struct {
	// EncryptionMethod string `xml:"EncryptionMethod>Algorithm"`
	X509Data    string `xml:"KeyInfo>X509Data>X509Certificate"`
	CipherValue string `xml:"CipherData>CipherValue"`
}

//SymmetricKey returns the private key contained in the EncryptedKey document
func (ek *EncryptedKey) SymmetricKey() (cipher.Block, error) {
	bs, err := base64.StdEncoding.DecodeString(ek.CipherValue)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(pem.Bytes)

	if err != nil {
		return nil, fmt.Errorf("cipher error: %v", err)
	}

	return block, nil
}

//Response is an abstraction type for handling the information in a SAML
//assertion
type Response struct {
	XMLName     xml.Name
	Destination string       `xml:"Destination,attr"`
	Issuer      string       `xml:"Issuer"`
	Value       string       `xml:",attr"`
	Key         EncryptedKey `xml:"EncryptedAssertion>EncryptedData>KeyInfo>EncryptedKey"`
	Data        string       `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
}

//Decrypt returns the byte slice contained in the encrypted data.
func (sr *Response) Decrypt() ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(sr.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 error: %v\n", err)
	}

	dst := make([]byte, len(data))

	k, err := sr.Key.SymmetricKey()
	if err != nil {
		return nil, fmt.Errorf("symmetric key error: %v\n", err)
	}

	k.Decrypt(dst, data)

	return dst, nil
}
