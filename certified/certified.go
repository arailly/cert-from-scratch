package certified

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/arailly/cert-from-scratch/privkey"
)

var (
	oidRSAEncryption           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidCommonName              = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// TODO: Specify following fields
// basicConstraints: CA:TRUE/FALSE
// keyUsage: keyCertSign, cRLSign/digitalSignature, keyEncipherment
// extendedKeyUsage (EKU): 通常なし（あっても CA 用）/serverAuth（必須）
// SAN: 任意（必須ではない）/必須（DNS名/IP）
// SKI/AKI: 推奨（チェーン用）/推奨
// Subject CN: 任意（CA名として入る）/必須ではない（SAN が優先）

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
	NotBefore time.Time `asn1:"utc"`
	NotAfter  time.Time `asn1:"utc"`
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

type BasicConstraints struct {
	CA      bool
	PathLen int `asn1:"optional"`
}

type modifier func(*TBSCertificate)

func newCertificate(privkey *privkey.RSAPrivateKey, modifiers ...modifier) *Certificate {
	signatureAlgorithm := AlgorithmIdentifier{
		Algorithm:  oidSHA256WithRSAEncryption,
		Parameters: asn1.NullRawValue,
	}

	name := Name{
		RDNSequence: []AttributeTypeAndValue{
			{Type: oidCommonName, Value: "localhost"},
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
			NotBefore: time.Now().UTC(),
			NotAfter:  time.Now().AddDate(1, 0, 0).UTC(), // Valid for 1 year
		},
		Subject:   name,
		PublicKey: subjectPublicKeyInfo,
	}

	for _, modify := range modifiers {
		modify(&tbsCertificate)
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

func NewCACertificate(privkey *privkey.RSAPrivateKey) *Certificate {
	// Issuer and Subject
	nameModifier := func(tbs *TBSCertificate) {
		caName := Name{
			RDNSequence: []AttributeTypeAndValue{
				{Type: oidCommonName, Value: "My CA"},
			},
		}
		tbs.Issuer = caName
		tbs.Subject = caName
	}

	// Basic Constraints
	bcModifier := func(tbs *TBSCertificate) {
		bc := BasicConstraints{
			CA:      true,
			PathLen: 0,
		}
		encodedBC, err := asn1.Marshal(bc)
		if err != nil {
			panic("failed to marshal basic constraints: " + err.Error())
		}
		bcExtension := Extension{
			ExtnID:    asn1.ObjectIdentifier{2, 5, 29, 19}, // OID for Basic Constraints
			Critical:  true,
			ExtnValue: encodedBC,
		}
		tbs.Extensions = append(tbs.Extensions, bcExtension)
	}

	// Key Usage
	kuModifier := func(tbs *TBSCertificate) {
		ku := asn1.BitString{
			Bytes:     []byte{0b000001100}, // keyCertSign(5), cRLSign(6)
			BitLength: 9,
		}
		encodedKU, err := asn1.Marshal(ku)
		if err != nil {
			panic("failed to marshal key usage: " + err.Error())
		}
		kuExtension := Extension{
			ExtnID:    asn1.ObjectIdentifier{2, 5, 29, 15}, // OID for Key Usage
			Critical:  true,
			ExtnValue: encodedKU,
		}
		tbs.Extensions = append(tbs.Extensions, kuExtension)
	}

	// Subject Key Identifier
	skiModifier := func(tbs *TBSCertificate) {
		skiHash := sha1.Sum(tbs.PublicKey.PublicKey.Bytes)
		tbs.Extensions = append(tbs.Extensions, Extension{
			ExtnID:    asn1.ObjectIdentifier{2, 5, 29, 14}, // OID for Subject Key Identifier
			Critical:  false,
			ExtnValue: skiHash[:],
		})
	}

	return newCertificate(
		privkey,
		nameModifier,
		bcModifier,
		kuModifier,
		skiModifier,
	)
}

func (b *Certificate) Marshal() ([]byte, error) {
	return asn1.Marshal(*b)
}
