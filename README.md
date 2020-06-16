# go-parsersa

[![GoDoc](https://godoc.org/HuguesGuilleus/go-parsersa?status.svg)](https://godoc.org/HuguesGuilleus/go-parsersa)

A simple package to parse RSA key from PEM.

## Instalation

```bash
go get github.com/HuguesGuilleus/go-parsersa
```

## Usage

```go
package main

import (
	"github.com/HuguesGuilleus/go-parsersa"
)

func main()  {
	k, err := parsersa.PrivFile("key.pem")
	if err != nil {
		fmt.Println("Error when load key:", err)
		return
	}

	// You can use the key
}
```
