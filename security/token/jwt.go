package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"hash"
	"strings"
)

// Algorithm specifies the HMAC cryptographic hash algorithm.
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"
)

// Header represents the JOSE header of a JSON Web Token.
type Header struct {
	Alg Algorithm `json:"alg"`
	Typ string    `json:"typ,omitempty"`
}

// Token represents a parsed and verified JSON Web Token.
type Token struct {
	Raw       string
	Header    Header
	Claims    *Claims
	Signature []byte
}

// HMACEngine provides RFC 7519 / RFC 7515 compliant JWT signing and verification.
// Built purely on standard library crypto with zero third-party dependencies.
type HMACEngine struct {
	algorithm Algorithm
	secret    []byte
}

// NewHMACEngine creates an HMACEngine with the chosen algorithm and secret key.
// The key must be at least 32 bytes (256 bits) to prevent brute-force attacks (RFC 8725 §3.2).
func NewHMACEngine(alg Algorithm, secret []byte) (*HMACEngine, error) {
	switch alg {
	case HS256, HS384, HS512:
	default:
		return nil, ErrAlgorithmMismatch
	}

	if len(secret) < 32 {
		return nil, ErrInvalidKey
	}

	return &HMACEngine{
		algorithm: alg,
		secret:    secret,
	}, nil
}

// Algorithm returns the engine's configured signature algorithm.
func (e *HMACEngine) Algorithm() Algorithm {
	return e.algorithm
}

// Sign serializes and cryptographically signs the provided claims.
func (e *HMACEngine) Sign(claims *Claims) (string, error) {
	if claims == nil {
		return "", ErrInvalidToken
	}

	header := Header{
		Alg: e.algorithm,
		Typ: "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := headerB64 + "." + claimsB64

	sig, err := e.computeHMAC([]byte(signingInput))
	if err != nil {
		return "", err
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

// Verify decodes, verifies the cryptographic signature, and validates the algorithm of a JWT.
func (e *HMACEngine) Verify(tokenString string) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// 1. Decode and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidToken
	}

	// Defense-in-depth against Algorithm Confusion / "none" attack (RFC 8725 §3.1)
	algStr := strings.TrimSpace(strings.ToLower(string(header.Alg)))
	if algStr == "" || algStr == "none" || strings.Contains(algStr, "none") {
		return nil, ErrAlgorithmMismatch
	}

	// Enforce strict algorithm equality with server configuration
	if header.Alg != e.algorithm {
		return nil, ErrAlgorithmMismatch
	}

	// 2. Decode signature
	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}

	// 3. Compute expected signature over "header.payload"
	signingInput := parts[0] + "." + parts[1]
	expectedSig, err := e.computeHMAC([]byte(signingInput))
	if err != nil {
		return nil, err
	}

	// 4. Constant-time comparison to prevent side-channel timing leaks
	if subtle.ConstantTimeCompare(expectedSig, actualSig) != 1 {
		return nil, ErrInvalidSignature
	}

	// 5. Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	return &Token{
		Raw:       tokenString,
		Header:    header,
		Claims:    &claims,
		Signature: actualSig,
	}, nil
}

func (e *HMACEngine) computeHMAC(data []byte) ([]byte, error) {
	var h func() hash.Hash
	switch e.algorithm {
	case HS256:
		h = sha256.New
	case HS384:
		h = sha512.New384
	case HS512:
		h = sha512.New
	default:
		return nil, ErrAlgorithmMismatch
	}

	mac := hmac.New(h, e.secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}
