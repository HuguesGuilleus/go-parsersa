// BSD 3-Clause License
// Copyright (c) 2020, HuguesGuilleus
// All rights reserved.

package parsersa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

// Try to read the file key or generate it if the file don't exist.
func GenPrivKey(file string, size int) (*rsa.PrivateKey, error) {
	// Read the file
	if k, err := PrivFile(file); err == nil {
		if s := k.N.BitLen(); s < size {
			return nil, fmt.Errorf("The key have a too short len: %d, want %d", s, size)
		}
		return k, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Generate the key
	k, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}

	// Save the new key
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k),
	})

	return k, nil
}

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
