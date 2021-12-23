package jwt

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"time"
)

type Service interface {
	Sign(Token)
	Verify(Token) bool
	Build() Builder
}

type serviceImpl struct {
	Algo    string
	Secret  string
	Timeout time.Duration
}

func NewService(algo string, secret string, timeout time.Duration) Service {
	return &serviceImpl{Algo: algo, Secret: secret, Timeout: timeout}
}

func (s *serviceImpl) Build() Builder {
	return &builderImpl{
		Algo:   s.Algo,
		Claims: make(Claims),
		Expiry: s.Timeout}
}

func (s *serviceImpl) Verify(t Token) bool {
	b64Sig := s.signPayload(t.Payload())
	tSig := t.Signature()
	return b64Sig == tSig && !t.IsExpired()
}

func (s *serviceImpl) Sign(t Token) {
	if t.IsExpired() {
		return
	}
	b64Sig := s.signPayload(t.Payload())
	t.Sign(b64Sig)
}

func (s *serviceImpl) signPayload(payload string) (base64Sig string) {
	secret := base64.RawURLEncoding.EncodeToString([]byte(s.Secret))
	hmacSha256 := hmac.New(crypto.SHA256.New, []byte(secret))
	hmacSha256.Write([]byte(payload))
	signature := hmacSha256.Sum(nil)
	b64sig := base64.RawURLEncoding.EncodeToString(signature)
	return b64sig
}
