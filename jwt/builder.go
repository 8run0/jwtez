package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type Builder struct {
	BuiltToken *Token
	Err        error
	Algo       string
	Claims     Claims
	Expiry     time.Duration
}

func (b *Builder) Token() (*Token, error) {
	if b.Err != nil {
		return nil, b.Err
	}
	if b.BuiltToken != nil {
		return b.BuiltToken, nil
	}
	b.BuiltToken = &Token{Header: Header{
		Alg: b.Algo,
		Typ: "JWT",
	}, Claims: b.Claims}
	return b.BuiltToken, nil
}

func (b *Builder) FromString(jwtStr string) *Builder {
	parts := strings.Split(jwtStr, ".")

	headerJson, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		b.Err = err
	}
	header := &Header{}
	err = json.Unmarshal(headerJson, header)
	if err != nil {
		b.Err = err
	}
	claimsJson, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		b.Err = err
	}
	var claims = map[string]string{}
	err = json.Unmarshal(claimsJson, &claims)
	if err != nil {
		b.Err = err
	}
	b64Sig := parts[2]
	b.BuiltToken = &Token{
		Header:          *header,
		Claims:          claims,
		Base64Signature: b64Sig,
	}
	return b
}

func (t *Token) AddClaim(key string, value string) *Token {
	t.Claims[key] = value
	return t
}
func (b *Builder) WithClaim(key string, value string) *Builder {
	b.Claims[key] = value
	return b
}
func (b *Builder) WithExpiryIn(duration time.Duration) *Builder {
	b.Expiry = duration
	expiry := strconv.FormatInt(time.Now().Add(duration).Unix(), 10)
	b.WithClaim("exp", expiry)
	return b
}
