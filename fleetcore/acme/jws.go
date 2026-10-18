package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// jwk is the public key an account uses (RFC 7517), the parts ACME needs.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func (k jwk) key() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		var c elliptic.Curve
		switch k.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		default:
			return nil, errors.New("unsupported curve")
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad key")
		}
		pub := &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !c.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("the key is not on the curve")
		}
		return pub, nil
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad key")
		}
		ei := new(big.Int).SetBytes(e)
		if !ei.IsInt64() || new(big.Int).SetBytes(n).BitLen() < 2048 {
			return nil, errors.New("RSA keys must be at least 2048 bits")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ei.Int64())}, nil
	}
	return nil, errors.New("unsupported key type")
}

// thumbprint is the RFC 7638 thumbprint of the key: how an account is told from another and what the key authorization is built on.
func (k jwk) thumbprint() string {
	var canon []byte
	switch k.Kty {
	case "EC":
		canon, _ = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{k.Crv, k.Kty, k.X, k.Y})
	default:
		canon, _ = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{k.E, k.Kty, k.N})
	}
	h := sha256.Sum256(canon)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type protected struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
	JWK   *jwk   `json:"jwk,omitempty"`
	KID   string `json:"kid,omitempty"`
}

type envelope struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// verify checks the signature of a flattened JWS with the key.
func (e envelope) verify(pub crypto.PublicKey, alg string) error {
	sig, err := b64(e.Signature)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	input := []byte(e.Protected + "." + e.Payload)
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		var h crypto.Hash
		var size int
		switch alg {
		case "ES256":
			h, size = crypto.SHA256, 32
			if p.Curve != elliptic.P256() {
				return errors.New("ES256 needs a P-256 key")
			}
		case "ES384":
			h, size = crypto.SHA384, 48
			if p.Curve != elliptic.P384() {
				return errors.New("ES384 needs a P-384 key")
			}
		default:
			return errors.New("the algorithm does not fit the key")
		}
		if len(sig) != 2*size {
			return errors.New("bad signature length")
		}
		var digest []byte
		if h == crypto.SHA256 {
			d := sha256.Sum256(input)
			digest = d[:]
		} else {
			d := sha512.Sum384(input)
			digest = d[:]
		}
		if !ecdsa.Verify(p, digest, new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])) {
			return errors.New("the signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		if alg != "RS256" {
			return errors.New("the algorithm does not fit the key")
		}
		d := sha256.Sum256(input)
		if err := rsa.VerifyPKCS1v15(p, crypto.SHA256, d[:], sig); err != nil {
			return errors.New("the signature does not verify")
		}
		return nil
	}
	return errors.New("unsupported key")
}
