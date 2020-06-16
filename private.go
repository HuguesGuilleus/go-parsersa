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

// Parse a private key from a file.
func PrivFile(file string) (*rsa.PrivateKey, error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Priv(content)
}

// Parse a RSA private key from a PEM.
func Priv(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("Need PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
