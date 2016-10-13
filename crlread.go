package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/boltdb/bolt"
	"io/ioutil"
	"os"
	"sync"
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
	dbFile := "crl.db"

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

	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("test"))
		return err
	})
	if err != nil {
		panic(err)
	}

	var waitGroup sync.WaitGroup

	for _, cert := range crlList.TBSCertList.RevokedCertificates {
		sNum := cert.SerialNumber.Bytes()
		bTime, err := cert.RevocationTime.GobEncode()
		if err != nil {
			panic(err)
		}
		waitGroup.Add(1)
		go func(db *bolt.DB, s []byte, t []byte) {
			err = db.Batch(func(tx *bolt.Tx) error {
				bucket := tx.Bucket([]byte("test"))
				if err != nil {
					return err
				}
				err = bucket.Put(s, t)
				if err != nil {
					return err
				}
				waitGroup.Done()
				return nil
			})
			if err != nil {
				panic(err)
			}
		}(db, sNum, bTime)
	}
	waitGroup.Wait()
}
