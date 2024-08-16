package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	name, err := filepath.Abs(filepath.Clean(os.Args[1]))
	if err != nil {
		log.Fatal(err)
	}
	b, err := os.ReadFile(name)
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
	fmt.Println(hex.EncodeToString(sum[:]))
	fmt.Println(hex.EncodeToString(sum[:4]))
}
