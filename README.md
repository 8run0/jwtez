# JWTEZ

JWT Token generator and service with support for the following sigining standards:

1. HS256

## Install

`go get github.com/8run0/jwtez`

## Usage

Create a new Service then use the services provided builder to build tokens for that service.  Sign with HS256 with the key and it will be used for all JWT tokens going forward.

```
    // New JWT Service With HS256 Hashing and the provided secret
	svc := jwt.NewService("HS256", "super-duper-random-secret-key-goes-here-min-of-256-bytes")
	// Build a New token with the Claims provided and set and expiry for a duration
	// in the future
	token, _ := svc.Build().
		WithClaim("user", "username").
		WithClaim("role", "admin").
		WithClaim("iat", strconv.FormatInt(time.Now().Unix(), 10)).
		WithExpiryIn(time.Hour * 24 * 365 * 100).Token()
	// Sign the token with the service
	svc.Sign(token)
	// Print the token in the standard '.' separated base64 encoded format
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOiI0NzkzODE1NDU4IiwiaWF0IjoiMTY0MDIxNTQ1OCIsInJvbGUiOiJhZG1pbiIsInVzZXIiOiJzdHV4bmV0In0.tq51cLI46J6e8CL9dk1Gl8hH4vMkXCdfzWzBiqbM6Co
	fmt.Println(token.String())

	// Rebuild token from the provided string
	parsedToken, _ := svc.Build().
		FromString(token.String()).Token()
	// Print the token in the standard '.' separated base64 encoded format
	// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOiI0NzkzODE1NDU4IiwiaWF0IjoiMTY0MDIxNTQ1OCIsInJvbGUiOiJhZG1pbiIsInVzZXIiOiJzdHV4bmV0In0.tq51cLI46J6e8CL9dk1Gl8hH4vMkXCdfzWzBiqbM6Co
	fmt.Println(parsedToken.String())
	// Verify that this rebuilt token is verified
	fmt.Println(svc.Verify(parsedToken))
    ```


