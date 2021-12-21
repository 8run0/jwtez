package internal

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultTyp            = "JWT"
	DefaultIss            = "bruno"
	DefaultExpireDuration = time.Hour
	DefaultSub            = "bruno-subject"
	DefaultAud            = "bruno-audience"
	DefaultSecret         = "brunos-secret-key"
)

var DefaultRegisterdClaims = map[string]string{"iss": DefaultIss, "exp": "", "sub": DefaultSub, "aud": DefaultAud, "iat": ""}
var DefaultPublicClaims = map[string]string{}
var DefaultPrivateClaims = map[string]string{}

type Token struct {
	Header    Header
	Claims    Claims
	Signature Signature
}

type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type Claims struct {
	RegisteredClaims RegisteredClaims
	PublicClaims     PublicClaims
	PrivateClaims    PrivateClaims
}

type RegisteredClaims map[string]string
type PublicClaims map[string]string
type PrivateClaims map[string]string

type Signature struct {
	SigningPayload string
	Signature      string
}

func NewDefault() *Token {
	token := &Token{
		Header: Header{
			Typ: DefaultTyp,
			Alg: "HMACSHA256"},
		Claims: Claims{
			RegisteredClaims: PopulateDefaultClaims(),
			PublicClaims:     DefaultPublicClaims,
			PrivateClaims:    DefaultPrivateClaims,
		},
	}
	token.Sign()
	return token
}
func (t *Token) String() string {
	hBytes, _ := json.Marshal(t.Header)
	header := strings.TrimRight(base64.URLEncoding.EncodeToString(hBytes), "=")
	cBytes, _ := json.Marshal(t.Claims)
	claims := strings.TrimRight(base64.URLEncoding.EncodeToString(cBytes), "=")
	return strings.Join([]string{header, claims, t.Signature.Signature}, ".")
}
func (t *Token) Sign() {
	sha := crypto.SHA256
	hasher := hmac.New(sha.New, []byte(DefaultSecret))
	hBytes, _ := json.Marshal(t.Header)
	header := strings.TrimRight(base64.URLEncoding.EncodeToString(hBytes), "=")
	cBytes, _ := json.Marshal(t.Claims)
	claims := strings.TrimRight(base64.URLEncoding.EncodeToString(cBytes), "=")
	signingString := strings.Join([]string{header, claims}, ".")
	hasher.Write([]byte(signingString))
	signature := strings.TrimRight(base64.URLEncoding.EncodeToString(hasher.Sum(nil)), "=")
	t.Signature.Signature = signature
	t.Signature.SigningPayload = signingString
}

func PopulateDefaultClaims() map[string]string {
	claims := DefaultRegisterdClaims
	expiry := time.Now().Local().Add(DefaultExpireDuration)
	claims["exp"] = fmt.Sprintf("%d", expiry.Unix())
	claims["iat"] = fmt.Sprintf("%d", time.Now().Unix())
	return claims
}

func (t *Token) Decode() string {
	hBytes, _ := json.Marshal(t.Header)
	cBytes, _ := json.Marshal(t.Claims)
	fmt.Printf("%s\n", t.Signature.Signature)
	return fmt.Sprintf("%s.%s.%s\n", hBytes, cBytes, t.Signature.Signature)

}
