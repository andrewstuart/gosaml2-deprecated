package saml

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"fmt"

	"github.com/lestrrat/go-libxml2"
	"github.com/lestrrat/go-xmlsec"
	"github.com/lestrrat/go-xmlsec/crypto"
	"github.com/lestrrat/go-xmlsec/dsig"
)

const xtx = `count(ancestor-or-self::dsig:Signature |
   here()/ancestor::dsig:Signature[1]) >
   count(ancestor-or-self::dsig:Signature)`

//Response is an abstraction type for handling the information in a SAML
//assertion
type Response struct {
	Destination string       `xml:"Destination,attr"`
	Issuer      string       `xml:"Issuer"`
	Value       string       `xml:",attr"`
	Key         EncryptedKey `xml:"EncryptedAssertion>EncryptedData>KeyInfo>EncryptedKey"`
	Data        string       `xml:"EncryptedAssertion>EncryptedData>CipherData>CipherValue"`
	Signature   string       `xml:"Signature>SignatureValue"`
	SigningCert string       `xml:"Signature>KeyInfor>X509Data>X509Certificate"`
	Digest      string       `xml:"Signature>SignedInfo>Reference>DigestValue"`
	Raw         []byte
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
	// sig, err := xmlBytes(sr.Digest)
	// if err != nil {
	// 	return err
	// }

	// re := regexp.MustCompile("(?sm)ds:Signature.*</ds:Signature>.*?<")

	xmlsec.Init()
	defer xmlsec.Shutdown()

	doc, err := libxml2.Parse(sr.Raw)
	if err != nil {
		return err
	}
	defer doc.Free()

	km, err := crypto.NewKeyManager()
	if err != nil {
		return err
	}
	defer km.Free()

	bs, err := xmlBytes(sr.SigningCert)
	if err != nil {
		return err
	}

	err = km.LoadCert(bs, crypto.KeyDataFormatCertPem, crypto.KeyDataType(crypto.KeyDataTypePublic))
	if err != nil {
		return err
	}

	ctx, err := dsig.NewCtx(km)
	if err != nil {
		return err
	}
	defer ctx.Free()

	ctx.Verify(doc)

	return ErrNoTrustedIDP
}
