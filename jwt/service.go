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
	Algo   string
	Secret string
}

const (
	DefaultExpireDuration = time.Hour
	DefaultSecret         = "brunos-secret-keybrunos-secret-keybrunos-secret-keybrunos-secret-key"
)

func NewDefaultService() Service {
	return &serviceImpl{Algo: "HS256", Secret: "randomstringgoeshere"}
}

func (s *serviceImpl) Build() Builder {
	return &builderImpl{
		Algo:   s.Algo,
		Claims: make(Claims)}
}

func (s *serviceImpl) Verify(t Token) bool {
	b64Sig := signPayload(t.Payload())
	tSig := t.Signature()
	return b64Sig == tSig && !t.IsExpired()
}

func (s *serviceImpl) Sign(t Token) {
	if t.IsExpired() {
		return
	}
	b64Sig := signPayload(t.Payload())
	t.Sign(b64Sig)
}

func signPayload(payload string) (base64Sig string) {
	secret := base64.RawURLEncoding.EncodeToString([]byte(DefaultSecret))
	hmacSha256 := hmac.New(crypto.SHA256.New, []byte(secret))
	hmacSha256.Write([]byte(payload))
	signature := hmacSha256.Sum(nil)
	b64sig := base64.RawURLEncoding.EncodeToString(signature)
	return b64sig
}
