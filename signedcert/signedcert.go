package signedcert

import (
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/arailly/cert-from-scratch/privkey"
)

var (
	oidRSAEncryption           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

type Certificate struct {
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

type RSAPublicKey struct {
	N *big.Int
	E int
}

type Extension struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool
	ExtnValue []byte
}

func New(privkey *privkey.RSAPrivateKey) *Certificate {
	signatureAlgorithm := AlgorithmIdentifier{
		Algorithm:  oidSHA256WithRSAEncryption,
		Parameters: asn1.NullRawValue,
	}

	name := Name{
		RDNSequence: []AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "Example Country"},
		},
	}

	// cf. https://tex2e.github.io/rfc-translater/html/rfc3279.html
	publicKey := RSAPublicKey{
		N: privkey.Public().N,
		E: privkey.Public().E,
	}
	encodedPublicKey, err := asn1.Marshal(publicKey)
	if err != nil {
		panic("failed to marshal public key: " + err.Error())
	}
	publicKeyBitString := asn1.BitString{
		Bytes:     encodedPublicKey,
		BitLength: len(encodedPublicKey) * 8,
	}
	subjectPublicKeyInfo := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		PublicKey: publicKeyBitString,
	}

	tbsCertificate := TBSCertificate{
		Version:      2,
		SerialNumber: 1,
		Signature:    signatureAlgorithm,
		Issuer:       name,
		Validity: Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(1, 0, 0), // Valid for 1 year
		},
		Subject:   name,
		PublicKey: subjectPublicKeyInfo,
	}

	encodedTBS, err := asn1.Marshal(tbsCertificate)
	if err != nil {
		panic("failed to marshal TBS certificate: " + err.Error())
	}
	hashed := sha256.Sum256(encodedTBS)
	signature, err := privkey.Sign(hashed[:])
	if err != nil {
		panic("failed to sign TBS certificate: " + err.Error())
	}

	return &Certificate{
		TBSCertificate:     tbsCertificate,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}
}

func (b *Certificate) Marshal() ([]byte, error) {
	return asn1.Marshal(*b)
}
