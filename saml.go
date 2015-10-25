package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"log"
	"regexp"
)

var pk crypto.PrivateKey
var cert tls.Certificate

func init() {
	var err error
	pfx := "../openid-sp-enc"
	cert, err = tls.LoadX509KeyPair(fmt.Sprintf("%s.crt", pfx), fmt.Sprintf("%s.key", pfx))
	if err != nil {
		log.Fatal(err)
	}
	pk = cert.PrivateKey
}

//EncryptedKey contains the decryption key data from the saml2 core and xmlenc
//standards.
type EncryptedKey struct {
	// EncryptionMethod string `xml:"EncryptionMethod>Algorithm"`
	X509Data    string `xml:"KeyInfo>X509Data>X509Certificate"`
	CipherValue string `xml:"CipherData>CipherValue"`
}

func xmlBytes(str string) ([]byte, error) {
	if len(str) == 0 {
		return nil, fmt.Errorf("No string to decode")
	}

	re := regexp.MustCompile("[ \t]")
	str = re.ReplaceAllString(str, "")

	if str[0] == '\n' {
		str = str[1:]
	}

	return base64.StdEncoding.DecodeString(str)
}

//SymmetricKey returns the private key contained in the EncryptedKey document
func (ek *EncryptedKey) SymmetricKey() (cipher.Block, error) {
	cipherText, err := xmlBytes(ek.CipherValue)
	if err != nil {
		return nil, err
	}

	var digest []byte
	//TODO use mask function if needed here
	// if digest != "" {
	// 	db, err = xmlBytes(digest)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Digest error %v", err)
	// 	}
	// }

	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		pt, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, pk, cipherText, digest)
		if err != nil {
			return nil, fmt.Errorf("rsa internal error: %v", err)
		}

		b, err := aes.NewCipher(pt)
		if err != nil {
			return nil, err
		}

		return b, nil
	}
	return nil, fmt.Errorf("no cipher for decoding symmetric key")
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
	k, err := sr.Key.SymmetricKey()

	if err != nil {
		return nil, fmt.Errorf("cannot decrypt, error retrieving private key: %v", err)
	}

	data, err := xmlBytes(sr.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 error: %v\n", err)
	}

	plainText := make([]byte, len(data))

	//Get CBC decrypter using IV
	c := cipher.NewCBCDecrypter(k, data[:aes.BlockSize])

	//Decrypt blocks
	c.CryptBlocks(plainText, data)

	//Remove padding (each padding byte is a uint8 equal to the length of the padding)
	padLength := plainText[len(plainText)-1]
	return plainText[:len(plainText)-int(padLength)], nil
}
