package utils

import (
	"fmt"
	"provider/database"
	"time"

	"github.com/golang-jwt/jwt"
)

// secret used to sign the jwt
var secret = []byte("my_secret_key")

// IssueJWT issues a new jwt based on the user's data
func IssueJWT(user database.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name":  user.Name,
		"email": user.Email,
		"roles": user.Roles,
		"exp":   time.Now().Add(60 * time.Minute).Unix(),
	})
	// Sign the token with the secret key
	return token.SignedString(secret)
}

// VerifyJWT is used to verify the jwt signature
func VerifyJWT(tokenString string) (*jwt.Token, error) {
	// Parse the token with the secret key
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	// Check if the signature is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token, nil
}

// DecodeJWT decodes the issue jwt
func DecodeJWT(tokenString string) (claims jwt.MapClaims, isValid bool) {
	// Decode the token and verify the signature
	decodedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		fmt.Println("Error decoding token:", err)
		return nil, false
	}

	// Get the claims from the decoded token
	claims, ok := decodedToken.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Invalid token claims")
		return nil, false
	}

	// Verify the expiration time
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		fmt.Println("Token has expired")
		return nil, false
	}

	return claims, true
}

// ClaimsToUser converts the jwt claims into the user object
func ClaimsToUser(claims jwt.MapClaims) (*database.User, error) {
	name, ok := claims["name"].(string)
	if !ok {
		return nil, fmt.Errorf("missing name claim")
	}
	email, ok := claims["email"].(string)
	if !ok {
		return nil, fmt.Errorf("missing email claim")
	}
	roles, ok := claims["roles"].(string)
	if !ok {
		return nil, fmt.Errorf("missing roles claim")
	}
	return &database.User{
		Name:  name,
		Email: email,
		Roles: roles,
	}, nil
}
