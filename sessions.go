package main

import (
	"errors"
	"fmt"
	"net/http"
)

var AuthError = errors.New("unauthentication")

func Authorize(req *http.Request) error {
	username := req.FormValue("username")
	user, exists := users[username]
	if !exists {
		fmt.Println("User not found")
		return AuthError
	}
	st, err := req.Cookie("session_token")
	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthError
	}
	csfr := req.Header.Get("csrf_token")
	if csfr == "" || csfr != user.CSRFToken {
		return AuthError
	}

	return nil
}
