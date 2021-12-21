package main

import (
	"fmt"
	"log"

	"github.com/8run0/jwtez/internal"
)

func main() {
	log.Printf("Starting JWTEZ server... ")
	token := internal.NewDefault()
	token.Sign()
	fmt.Println(token.String())
	fmt.Println(token.Decode())
}
