package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

type Builder interface {
	FromString(string) Builder
	WithAlgo(algo string) Builder
	WithClaim(key string, value string) Builder
	WithExpiryIn(duration time.Duration) Builder
	Token() (Token, error)
}

type builderImpl struct {
	BuiltToken Token
	Err        error
	Claims     Claims
	Algo       string
	Expiry     time.Duration
}

func (b *builderImpl) Token() (Token, error) {
	if b.Err != nil {
		return nil, b.Err
	}
	if b.BuiltToken != nil {
		return b.BuiltToken, nil
	}
	b.BuiltToken = &tokenImpl{Header: Header{
		Alg: b.Algo,
		Typ: "JWT",
	}, Claims: b.Claims}
	return b.BuiltToken, nil
}

func (b *builderImpl) FromString(jwtStr string) Builder {
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
	b.BuiltToken = &tokenImpl{
		Header:          *header,
		Claims:          claims,
		Base64Signature: b64Sig,
	}
	return b
}

func (b *builderImpl) WithAlgo(algo string) Builder {
	b.Algo = algo
	return b
}
func (t *tokenImpl) AddClaim(key string, value string) Token {
	t.Claims[key] = value
	return t
}
func (b *builderImpl) WithClaim(key string, value string) Builder {
	b.Claims[key] = value
	return b
}
func (b *builderImpl) WithExpiryIn(duration time.Duration) Builder {
	b.Expiry = duration
	expiry := strconv.FormatInt(time.Now().Add(duration).Unix(), 10)
	b.WithClaim("exp", expiry)
	return b
}
