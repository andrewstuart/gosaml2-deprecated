package saml

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
)

//EncryptedKey contains the decryption key data from the saml2 core and xmlenc
//standards.
type EncryptedKey struct {
	// EncryptionMethod string `xml:"EncryptionMethod>Algorithm"`
	X509Data         string `xml:"KeyInfo>X509Data>X509Certificate"`
	CipherValue      string `xml:"CipherData>CipherValue"`
	EncryptionMethod EncryptionMethod
}

//EncryptionMethod specifies the type of encryption that was used.
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

//Well-known encryption methods
const (
	MethodRSAOAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
)

//SymmetricKey returns the private key contained in the EncryptedKey document
func (ek *EncryptedKey) SymmetricKey(cert tls.Certificate) (cipher.Block, error) {
	cipherText, err := xmlBytes(ek.CipherValue)
	if err != nil {
		return nil, err
	}

	switch pk := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		switch ek.EncryptionMethod.Algorithm {
		case MethodRSAOAEP:
			pt, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, pk, cipherText, nil)
			if err != nil {
				return nil, fmt.Errorf("rsa internal error: %v", err)
			}

			b, err := aes.NewCipher(pt)
			if err != nil {
				return nil, err
			}

			return b, nil
		default:
			return nil, fmt.Errorf("unsupported encryption algorithm: %s", ek.EncryptionMethod.Algorithm)
		}
	}
	return nil, fmt.Errorf("no cipher for decoding symmetric key")
}
