/*-
 * Copyright 2015 Square Inc.
 * Copyright 2014 CoreOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pkix

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	rsaPrivateKeyPEMBlockType   = "RSA PRIVATE KEY"
	ecdsaPrivateKeyPEMBlockType = "EC PRIVATE KEY"
)

// CreateRSAKey creates a new Key using RSA algorithm
func CreateRSAKey(rsaBits int) (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}

// CreateECDSAKey creates a new Key using RSA algorithm
func CreateECDSAKey(curvName string) (*Key, error) {
	var (
		priv *ecdsa.PrivateKey
		err  error
	)

	switch curvName {
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("Unrecognized elliptic curve: %q", curvName)
	}
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}

// Key contains a public-private keypair
type Key struct {
	Public  crypto.PublicKey
	Private crypto.PrivateKey
}

// NewKey returns a new public-private keypair Key type
func NewKey(pub crypto.PublicKey, priv crypto.PrivateKey) *Key {
	return &Key{Public: pub, Private: priv}
}

// NewKeyFromPrivateKeyPEM inits Key from PEM-format rsa private key bytes
func NewKeyFromPrivateKeyPEM(data []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}

	switch pemBlock.Type {
	case rsaPrivateKeyPEMBlockType:
		priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return NewKey(&priv.PublicKey, priv), nil
	case ecdsaPrivateKeyPEMBlockType:
		priv, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return NewKey(&priv.PublicKey, priv), nil
	default:
		return nil, fmt.Errorf("unmatched type or headers: %s", pemBlock.Type)
	}
}

// NewKeyFromEncryptedPrivateKeyPEM inits Key from encrypted PEM-format rsa private key bytes
func NewKeyFromEncryptedPrivateKeyPEM(data []byte, password []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType && pemBlock.Type != ecdsaPrivateKeyPEMBlockType {
		return nil, fmt.Errorf("unmatched type or headers: %s", pemBlock.Type)
	}

	b, err := x509.DecryptPEMBlock(pemBlock, password)
	if err != nil {
		return nil, err
	}

	if pemBlock.Type == rsaPrivateKeyPEMBlockType {
		priv, err := x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return nil, err
		}

		return NewKey(&priv.PublicKey, priv), nil
	}

	priv, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return NewKey(&priv.PublicKey, priv), nil
}

// ExportPrivate exports PEM-format private key
func (k *Key) ExportPrivate() ([]byte, error) {
	var privPEMBlock *pem.Block
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		privPEMBlock = &pem.Block{
			Type:  rsaPrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	case *ecdsa.PrivateKey:
		privBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		privPEMBlock = &pem.Block{
			Type:  ecdsaPrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	default:
		return nil, errors.New("only RSA and ECDRSA private key are supported")
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, privPEMBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExportEncryptedPrivate exports encrypted PEM-format private key
func (k *Key) ExportEncryptedPrivate(password []byte) ([]byte, error) {
	var (
		privBytes []byte
		err       error
		pemType   string
	)
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		privBytes, pemType = x509.MarshalPKCS1PrivateKey(priv), rsaPrivateKeyPEMBlockType
	case *ecdsa.PrivateKey:
		privBytes, err = x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pemType = ecdsaPrivateKeyPEMBlockType
	default:
		return nil, errors.New("only RSA private key is supported")
	}

	privPEMBlock, err := x509.EncryptPEMBlock(rand.Reader, pemType, privBytes, password, x509.PEMCipher3DES)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, privPEMBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// Id is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	encodedpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedpub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubhash := sha1.New()
	pubhash.Write(subPKI.SubjectPublicKey.Bytes)
	return pubhash.Sum(nil), nil
}
