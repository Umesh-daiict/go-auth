package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func hashPassword(password string) (string, error) {
	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func checkPasswordHash(hashedPassword, password string) bool {
	// Compare the hashed password with the provided password
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	fmt.Println("err", err)
	return err == nil
}

func generateSessionToken(len int) string {
	random := make([]byte, len)
	if _, err := rand.Read(random); err != nil {
		fmt.Println("Error generating random bytes:", err)
	}
	return base64.StdEncoding.EncodeToString(random)

}
