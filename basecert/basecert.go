package basecert

import (
	"encoding/asn1"
	"time"
)

type Certificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type TBSCertificate struct {
	Version      int `asn1:"tag:0,explicit"`
	SerialNumber int
	Signature    AlgorithmIdentifier
	Issuer       Name
	Validity     Validity
	Subject      Name
	PublicKey    SubjectPublicKeyInfo
}

type AlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

type Name struct {
	RDNSequence []AttributeTypeAndValue `asn1:"set"`
}

type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value string
}

type Validity struct {
	NotBefore time.Time `asn1:"utc"`
	NotAfter  time.Time `asn1:"utc"`
}

type SubjectPublicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

func New() *Certificate {
	signatureAlgorithm := AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // RSA encryption
	}

	zeros := make([]byte, 256)
	bitStringWithZeros := asn1.BitString{
		Bytes:     zeros,
		BitLength: len(zeros) * 8,
	}

	name := Name{
		RDNSequence: []AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "localhost"},
		},
	}

	tbsCertificate := TBSCertificate{
		Version:      2,
		SerialNumber: 1,
		Signature:    signatureAlgorithm,
		Issuer:       name,
		Validity: Validity{
			NotBefore: time.Now().UTC(),
			NotAfter:  time.Now().AddDate(1, 0, 0).UTC(), // Valid for 1 year
		},
		Subject: name,
		PublicKey: SubjectPublicKeyInfo{
			Algorithm: signatureAlgorithm,
			PublicKey: bitStringWithZeros,
		},
	}

	return &Certificate{
		TBSCertificate:     tbsCertificate,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     bitStringWithZeros,
	}
}

func (b *Certificate) Marshal() ([]byte, error) {
	return asn1.Marshal(*b)
}
