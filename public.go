// BSD 3-Clause License
// Copyright (c) 2020, HuguesGuilleus
// All rights reserved.

package parsersa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// Parse a public key from a file.
func PublicFile(file string) (*rsa.PublicKey, error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Public(content)
}

// Parse a RSA public key from a PEM.
func Public(raw []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("Need PEM block")
	}

	if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return k, nil
	}

	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if pub, ok := k.(*rsa.PublicKey); ok {
		return pub, nil
	}
	return nil, errors.New("The key is not a *rsa.PublicKey")
}
