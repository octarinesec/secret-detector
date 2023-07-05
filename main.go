package main

import (
	"fmt"
	"github.com/octarinesec/secret-detector/pkg/dataformat"
	"github.com/octarinesec/secret-detector/pkg/scanner"
	"github.com/octarinesec/secret-detector/pkg/secrets"
	"strings"
)

func printScanOutput(ds []secrets.DetectedSecret, err error) {
	fmt.Println("secrets: ")
	for _, d := range ds {
		fmt.Printf("\ttype: %s\n", d.Type)
		fmt.Printf("\tkey: %s\n", d.Key)
		fmt.Printf("\tvalue: %s\n", d.Value)
	}
	fmt.Println("err: ", err)
}

func main() {
	scanner := scanner.NewDefaultScanner()

	command := "ENV GITHUB_KEY=ghu_bWIj6excOoiobxoT_g0Ke1BChnXsuH_6UKpr"
	ds, err := scanner.ScanStringWithFormat(command, dataformat.Command)
	printScanOutput(ds, err)

	pk := "-----BEGIN DSA PRIVATE KEY-----\\nwxyz+ABC=\\n-----END DSA PRIVATE KEY-----"
	ds, err = scanner.ScanReader(strings.NewReader(pk))
	printScanOutput(ds, err)

	envvars := map[string]string{
		"PATH":     "/usr/bin",
		"PASSWORD": "my_secret_pass",
	}
	for k, v := range envvars {
		ds, err := scanner.Scan(k + ": " + v)
		printScanOutput(ds, err)
	}
}
