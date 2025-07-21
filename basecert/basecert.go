package basecert

import (
	"encoding/asn1"
	"time"
)

type BaseCertificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type TBSCertificate struct {
	Version         int `asn1:"tag:0,explicit"`
	SerialNumber    int
	Signature       AlgorithmIdentifier
	Issuer          Name
	Validity        Validity
	Subject         Name
	PublicKey       SubjectPublicKeyInfo
	IssuerUniqueID  asn1.BitString `asn1:"tag:1,optional,omitempty"`
	SubjectUniqueID asn1.BitString `asn1:"tag:2,optional,omitempty"`
	Extensions      []Extension    `asn1:"tag:3,explicit,optional,omitempty"`
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters any `asn1:"optional"`
}

type Name struct {
	RDNSequence []AttributeTypeAndValue `asn1:"set"`
}

type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value string
}

type Validity struct {
	NotBefore time.Time `asn1:"generalized"`
	NotAfter  time.Time `asn1:"generalized"`
}

type SubjectPublicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool
	ExtnValue []byte
}

func New() *BaseCertificate {
	signatureAlgorithm := AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // RSA encryption
		Parameters: asn1.NullRawValue,
	}

	zeros := make([]byte, 256)
	bitStringWithZeros := asn1.BitString{
		Bytes:     zeros,
		BitLength: len(zeros) * 8,
	}

	name := Name{
		RDNSequence: []AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "Example Country"},
		},
	}

	tbsCertificate := TBSCertificate{
		Version:      3,
		SerialNumber: 1,
		Signature:    signatureAlgorithm,
		Issuer:       name,
		Validity: Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(1, 0, 0), // Valid for 1 year
		},
		Subject: name,
		PublicKey: SubjectPublicKeyInfo{
			Algorithm: signatureAlgorithm,
			PublicKey: bitStringWithZeros,
		},
	}

	return &BaseCertificate{
		TBSCertificate:     tbsCertificate,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     bitStringWithZeros,
	}
}

func (b *BaseCertificate) Marshal() ([]byte, error) {
	return asn1.Marshal(*b)
}
