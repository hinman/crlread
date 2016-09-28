package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s CRL_FILE CERT_FILE\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	crlFile := flag.Arg(0)
	crtFile := flag.Arg(1)

	crlBytes, err := ioutil.ReadFile(crlFile)

	if err != nil {
		panic(err)
	}

	crtBytes, err := ioutil.ReadFile(crtFile)
	if err != nil {
		panic(err)
	}

	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		panic(err)
	}

	crlList, err := x509.ParseCRL(crlBytes)
	if err != nil {
		panic(err)
	}

	err = crt.CheckCRLSignature(crlList)
	if err != nil {
		panic(err)
	}

	var name pkix.Name

	name.FillFromRDNSequence(&crlList.TBSCertList.Issuer)

	for _, cert := range crlList.TBSCertList.RevokedCertificates {
		fmt.Printf("%v, %v\n", cert.SerialNumber, cert.RevocationTime)
	}

	fmt.Printf("%v\n", name.CommonName)
}
