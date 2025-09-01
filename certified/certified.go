package certified

import (
	"crypto/rsa"
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
	// X.509 Extension OIDs
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtSubjectKeyId     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtAuthorityKeyId   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidServerAuth          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
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

func sign(privkey *privkey.RSAPrivateKey, tbsCertificate *TBSCertificate) *Certificate {
	encodedTBS, err := asn1.Marshal(*tbsCertificate)
	if err != nil {
		panic("failed to marshal TBS certificate: " + err.Error())
	}
	hashed := sha256.Sum256(encodedTBS)
	signature, err := privkey.Sign(hashed[:])
	if err != nil {
		panic("failed to sign TBS certificate: " + err.Error())
	}

	return &Certificate{
		TBSCertificate:     *tbsCertificate,
		SignatureAlgorithm: tbsCertificate.Signature,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}
}

func newSubjectPublicKey(pubKey *rsa.PublicKey) *asn1.BitString {
	encodedPublicKey, err := asn1.Marshal(RSAPublicKey{
		N: pubKey.N,
		E: pubKey.E,
	})
	if err != nil {
		panic("failed to marshal public key: " + err.Error())
	}
	return &asn1.BitString{
		Bytes:     encodedPublicKey,
		BitLength: len(encodedPublicKey) * 8,
	}
}

func NewCACertificate(key *privkey.RSAPrivateKey) *Certificate {
	caName := Name{
		RDNSequence: []AttributeTypeAndValue{
			{Type: oidCommonName, Value: "My CA"},
		},
	}

	// 公開鍵情報
	subjectPublicKeyInfo := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		PublicKey: *newSubjectPublicKey(key.Public()),
	}

	// 拡張領域
	var extensions []Extension

	// Basic Constraints
	bc := BasicConstraints{
		CA:      true,
		PathLen: 0,
	}
	encodedBC, err := asn1.Marshal(bc)
	if err != nil {
		panic("failed to marshal basic constraints: " + err.Error())
	}
	extensions = append(extensions, Extension{
		ExtnID:    oidExtBasicConstraints,
		Critical:  true,
		ExtnValue: encodedBC,
	})

	// Key Usage
	ku := asn1.BitString{
		Bytes:     []byte{0b00000110}, // keyCertSign(5), cRLSign(6)
		BitLength: 7,
	}
	encodedKU, err := asn1.Marshal(ku)
	if err != nil {
		panic("failed to marshal key usage: " + err.Error())
	}
	extensions = append(extensions, Extension{
		ExtnID:    oidExtKeyUsage,
		Critical:  true,
		ExtnValue: encodedKU,
	})

	// Subject Key Identifier
	skiHash := sha1.Sum(subjectPublicKeyInfo.PublicKey.Bytes)
	extensions = append(extensions, Extension{
		ExtnID:    oidExtSubjectKeyId,
		Critical:  false,
		ExtnValue: skiHash[:],
	})

	// Authority Key Identifier
	extensions = append(extensions, Extension{
		ExtnID:    oidExtAuthorityKeyId,
		Critical:  false,
		ExtnValue: skiHash[:],
	})

	tbs := &TBSCertificate{
		Version:      2,
		SerialNumber: 1,
		Signature: AlgorithmIdentifier{
			Algorithm:  oidSHA256WithRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		Issuer: caName,
		Validity: Validity{
			NotBefore: time.Now().UTC(),
			NotAfter:  time.Now().AddDate(1, 0, 0).UTC(),
		},
		Subject:    caName,
		PublicKey:  subjectPublicKeyInfo,
		Extensions: extensions,
	}

	return sign(key, tbs)
}

func NewServerCertificate(
	key *privkey.RSAPrivateKey,
	caKey *privkey.RSAPrivateKey,
	caCert *Certificate,
) *Certificate {
	// Issuer
	issuerName := Name{
		RDNSequence: []AttributeTypeAndValue{
			{Type: oidCommonName, Value: "My CA"},
		},
	}

	// Subject (Server)
	subjectName := Name{
		RDNSequence: []AttributeTypeAndValue{
			{Type: oidCommonName, Value: "localhost"},
		},
	}

	// 公開鍵情報
	subjectPublicKeyInfo := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm:  oidRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		PublicKey: *newSubjectPublicKey(key.Public()),
	}

	// 拡張領域
	var extensions []Extension

	// Basic Constraints
	bc := BasicConstraints{
		CA: false,
	}
	encodedBC, err := asn1.Marshal(bc)
	if err != nil {
		panic("failed to marshal basic constraints: " + err.Error())
	}
	extensions = append(extensions, Extension{
		ExtnID:    oidExtBasicConstraints,
		Critical:  true,
		ExtnValue: encodedBC,
	})

	// Key Usage
	ku := asn1.BitString{
		Bytes:     []byte{0b10100000}, // digitalSignature(0), keyEncipherment(2)
		BitLength: 3,
	}
	encodedKU, err := asn1.Marshal(ku)
	if err != nil {
		panic("failed to marshal key usage: " + err.Error())
	}
	extensions = append(extensions, Extension{
		ExtnID:    oidExtKeyUsage,
		Critical:  true,
		ExtnValue: encodedKU,
	})

	// FIX: following extensions don't work

	// // Extended Key Usage
	// eku := []asn1.ObjectIdentifier{
	// 	oidServerAuth, // serverAuth
	// }
	// encodedEKU, err := asn1.Marshal(eku)
	// if err != nil {
	// 	panic("failed to marshal extended key usage: " + err.Error())
	// }
	// extensions = append(extensions, Extension{
	// 	ExtnID:    oidExtExtendedKeyUsage,
	// 	Critical:  false,
	// 	ExtnValue: encodedEKU,
	// })

	// // Subject Alternative Name
	// san := []string{"localhost", "127.0.0.1"}
	// encodedSAN, err := asn1.Marshal(san)
	// if err != nil {
	// 	panic("failed to marshal subject alternative name: " + err.Error())
	// }
	// extensions = append(extensions, Extension{
	// 	ExtnID:    oidExtSubjectAltName,
	// 	Critical:  false,
	// 	ExtnValue: encodedSAN,
	// })

	// // Subject Key Identifier
	// skiHash := sha1.Sum(subjectPublicKeyInfo.PublicKey.Bytes)
	// extensions = append(extensions, Extension{
	// 	ExtnID:    oidExtSubjectKeyId,
	// 	Critical:  false,
	// 	ExtnValue: skiHash[:],
	// })

	// // Authority Key Identifier
	// var issuerSKI []byte
	// for _, caExt := range caCert.TBSCertificate.Extensions {
	// 	if caExt.ExtnID.Equal(oidExtSubjectKeyId) {
	// 		issuerSKI = caExt.ExtnValue
	// 		break
	// 	}
	// }
	// if len(issuerSKI) == 0 {
	// 	panic("CA certificate does not have Subject Key Identifier")
	// }

	// extensions = append(extensions, Extension{
	// 	ExtnID:    oidExtAuthorityKeyId,
	// 	Critical:  false,
	// 	ExtnValue: issuerSKI,
	// })

	tbs := TBSCertificate{
		Version:      2,
		SerialNumber: 2,
		Signature: AlgorithmIdentifier{
			Algorithm:  oidSHA256WithRSAEncryption,
			Parameters: asn1.NullRawValue,
		},
		Issuer: issuerName,
		Validity: Validity{
			NotBefore: time.Now().UTC(),
			NotAfter:  time.Now().AddDate(1, 0, 0).UTC(),
		},
		Subject:    subjectName,
		PublicKey:  subjectPublicKeyInfo,
		Extensions: extensions,
	}

	return sign(caKey, &tbs)
}

func (b *Certificate) Marshal() ([]byte, error) {
	return asn1.Marshal(*b)
}
