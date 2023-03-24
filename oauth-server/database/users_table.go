package database

import (
	"encoding/base64"
	"fmt"
)

// User represents the DB record for users table
type User struct {
	ID       string
	Name     string
	Email    string
	Password string
	Roles    string
}

var usersTable = []*User{
	{
		ID:       "af8ab5ea-8cc9-44a0-8d83-c4e9462166bc",
		Name:     "John Doe",
		Email:    "john.doe@email.com",
		Password: "ampq", // jjj
		Roles:    "*",
	},
	{
		ID:       "2ea086fe-d0e1-4e05-b24b-d954c45a3f52",
		Name:     "Marion Ruhl",
		Email:    "marion.ruhl@email.com",
		Password: "cGFzc3dvcmQ=", // password
		Roles:    "user",
	},
	{
		ID:       "bde77f50-7a67-4ce2-88a0-3ad3fcc05340",
		Name:     "Angela Coghill",
		Email:    "angela.coghill@email.com",
		Password: "YW5nZWxhY29nMTIzNDU=", // angelacog12345
		Roles:    "user",
	},
}

func FindUserByEmailAndPassword(email, password string) *User {
	for _, user := range usersTable {
		if user.Email == email && user.Password == base64.StdEncoding.EncodeToString([]byte(password)) {
			return user
		}
	}
	fmt.Printf("Not found user %s with password %s", email, base64.StdEncoding.EncodeToString([]byte(password)))
	return nil
}

func FindUserByEmail(email string) *User {
	for _, user := range usersTable {
		if user.Email == email {
			return user
		}
	}
	return nil
}
