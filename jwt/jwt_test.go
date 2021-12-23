package jwt_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/8run0/jwtez/jwt"
)

var jwtSvc = jwt.NewService("HS256", "ksdjhfa8asldkjflk323lk2j4l2kfjsx8c8xckljzxcl", time.Second*30)

const (
	tokenSignedExpired    = "eyJUeXAiOiJKV1QiLCJBbGciOiJIUzI1NiJ9.eyJleHAiOiIxNjQwMTM3MzkyIiwiamZlIjoibGwiLCJtb2QiOiIxMjI7MTMiLCJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImJydW5vIn0.M_xny9I69nAPZAPDLfOj0-2BGLVreeUp6e4P-MMQt7s"
	tokenSignedNotExpired = "eyJUeXAiOiJKV1QiLCJBbGciOiJIUzI1NiJ9.eyJleHAiOiIxOTU1NDk4NjYzIiwiamZlIjoibGwiLCJtb2QiOiIxMjI7MTMiLCJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImJydW5vIn0.ObL2cBfeIMhiQKQnc0hLuL1Z8dXs4KeIDThfvpxSjjw"
	tokenUnsignedExpired  = "eyJUeXAiOiJKV1QiLCJBbGciOiJIUzI1NiJ9.eyJleHAiOiIxOTU1NDk4NjYzIiwiamZlIjoibGwiLCJtb2QiOiIxMjI7MTMiLCJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImJydW5vIn0.FSZB9qX6EOWg0Da3jz3c4Gu1cSXoywmIQBqwwrdTgWs"
	tokenBadClaims        = "eyJUeXAiOiJKV1QiLCJBbGciOiJIUzI1NiJ9.^^.badsignature"
	corruptToken          = "^corruptheader.^corruptpayload.^corruptsignature"
	tokenNoExpiry         = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCJ9.FSZB9qX6EOWg0Da3jz3c4Gu1cSXoywmIQBqwwrdTgWs"
	tokenInvalidExpiry    = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCIsImV4cCI6InRoaXNpc2ludmFsaWQifQ.FSZB9qX6EOWg0Da3jz3c4Gu1cSXoywmIQBqwwrdTgWs"
)

var tokenTests = []struct {
	description   string
	jwtSvc        *jwt.Service
	inputJwtToken string
	willError     bool
}{
	{"Generate,Sign and Verify JWT Token - WithClaims", jwtSvc, "", false},
	{"Parse JWT Token - Corrupt Token", jwtSvc, corruptToken, true},
	{"Parse JWT Token - Blank Claims Token", jwtSvc, tokenBadClaims, true},
	{"Parse JWT Token - No Expiry Claim Token", jwtSvc, tokenNoExpiry, true},
	{"Parse JWT Token - Invalid Expiry Claim Token", jwtSvc, tokenInvalidExpiry, true},
	{"Parse JWT Token - Signed, Not Expired", jwtSvc, tokenSignedNotExpired, false},
	{"Parse JWT Token - Signed, Expired", jwtSvc, tokenSignedExpired, false},
	{"Parse JWT Token - Unsigned, Expired", jwtSvc, tokenUnsignedExpired, false},
	{"Verify JWT Token - Invalid Token", jwtSvc, corruptToken, true},
	{"Verify JWT Token - Signed, Not Expired", jwtSvc, tokenSignedNotExpired, false},
	{"Verify JWT Token - Signed, Expired", jwtSvc, tokenSignedExpired, false},
	{"Verify JWT Token - Unsigned, Expired", jwtSvc, tokenUnsignedExpired, false},
}

func TestJwtSvc(t *testing.T) {
	for _, tt := range tokenTests {
		fmt.Printf("[%s]\n", tt.description)
		var token *jwt.Token
		if tt.inputJwtToken == "" {
			tkn, err := tt.jwtSvc.Build().WithClaim("test", "test").WithExpiryIn(time.Hour).Token()
			token = tkn
			if err != nil && !tt.willError {
				t.Errorf("%s - unexpected error %s inputJwtToken:%s token%s willError%t", tt.description, err, tt.inputJwtToken, token.String(), tt.willError)
			}
			if tt.willError {
				continue
			}
		} else {
			tkn, err := tt.jwtSvc.Build().FromString(tt.inputJwtToken).Token()
			token = tkn
			if err != nil && !tt.willError {
				t.Errorf("%s - unexpected error %s inputJwtToken:%s token%s willError%t", tt.description, err, tt.inputJwtToken, token.String(), tt.willError)
			}
			if token != nil {
				token.IsExpired()
			}
			if tt.willError {
				continue
			}
			tkn.AddClaim("test", "test")
		}
		verified := tt.jwtSvc.Verify(token)
		if verified {
			t.Errorf("%s - unexpected verification inputJwtToken:%s token%s willError%t", tt.description, tt.inputJwtToken, token.String(), tt.willError)
		}
		if token.GetClaim("test") != "test" {
			t.Errorf("%s - unexpected missing test claim inputJwtToken:%s token%s willError%t", tt.description, tt.inputJwtToken, token.String(), tt.willError)
		}
		tt.jwtSvc.Sign(token)
		verified = tt.jwtSvc.Verify(token)
		if !token.IsExpired() && !verified {
			t.Errorf("%s - unexpected post sign verification inputJwtToken:%s token%s willError%t", tt.description, tt.inputJwtToken, token.String(), tt.willError)
		}
		jwtValidator, _ := regexp.Compile("^[A-Za-z0-9-_=]+.[A-Za-z0-9-_=]+.?[A-Za-z0-9-_.+/=]*$")
		isJWT := jwtValidator.Match([]byte(token.String()))
		if !isJWT {
			t.Errorf("%s - unexpected output not a JWT inputJwtToken:%s token%s willError%t", tt.description, tt.inputJwtToken, token.String(), tt.willError)
		}
	}
}
