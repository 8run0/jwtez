package jwt

import (
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type Token struct {
	Header          Header
	Claims          Claims
	Base64Signature string
}

type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}
type Claims map[string]string

func (t *Token) Sign(base64Sig string) {
	t.Base64Signature = base64Sig
}
func (t *Token) Signature() string {
	return t.Base64Signature
}
func (h *Header) Base64String() string {
	hBytes, _ := json.Marshal(h)
	return toBase64(hBytes)
}
func (c *Claims) Base64String() string {
	cBytes, _ := json.Marshal(c)
	return toBase64(cBytes)
}
func (t *Token) GetClaim(key string) string {
	val := t.Claims[key]
	return val
}
func (t *Token) IsExpired() bool {
	expVal := t.Claims["exp"]
	if expVal == "" {
		return true
	}
	epoch, err := strconv.ParseInt(expVal, 10, 64)
	if err != nil {
		return true
	}
	expiry := time.Unix(epoch, 0)
	return expiry.Before(time.Now())
}
func (t *Token) String() string {
	return strings.Join([]string{t.Header.Base64String(), t.Claims.Base64String(), t.Base64Signature}, ".")
}
func toBase64(in []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(in), "=")
}
func (t *Token) Payload() string {
	payload := strings.Join(
		[]string{t.Header.Base64String(),
			t.Claims.Base64String()},
		".")
	return payload
}
