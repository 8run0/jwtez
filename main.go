package main

import (
	"fmt"
	"log"
	"time"

	"github.com/8run0/jwtez/jwt"
)

func main() {
	log.Printf("Starting JWTEZ server... ")

	jwtSvc := jwt.NewDefaultService()

	token, _ := jwtSvc.Build().
		WithClaim("username", "bruno").
		WithClaim("role", "admin").
		WithExpiryIn(time.Hour * 24 * 365 * 10).Token()

	fmt.Println(jwtSvc.Verify(token))
	jwtSvc.Sign(token)
	fmt.Println(jwtSvc.Verify(token))
	fmt.Println(token.String())
	token.AddClaim("mod", "122;13").
		AddClaim("jfe", "ll")

	fmt.Println(token.String())
	fmt.Println(jwtSvc.Verify(token))

	jwtSvc.Sign(token)
	fmt.Println(jwtSvc.Verify(token))
	fmt.Println(token.String())

	parseToken, _ := jwtSvc.Build().
		FromString(token.String()).Token()

	fmt.Println("----PARSED TOKEN---")
	fmt.Println(parseToken.String())
	fmt.Println(jwtSvc.Verify(parseToken))

	t, _ := jwtSvc.Build().WithClaim("test", "test").Token()

	fmt.Println(t)
}
