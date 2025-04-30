package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string `json:"hashed_password"`
	SessionToken   string `json:"session_token"`
	CSRFToken      string `json:"csrf_token"`
}

var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
	fmt.Printf("runnig on port :8080.....")
}

// Handle user registration
func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(password) < 8 || len(username) < 8 {
		http.Error(w, "Username and password must be at least 8 characters long", http.StatusBadRequest)
		return
	}
	if _, exists := users[username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}
	hashedPassword, _ := hashPassword(password)

	users[username] = Login{
		HashedPassword: hashedPassword,
	}
	fmt.Fprintf(w, "User %s registered successfully", username)

}
func login(w http.ResponseWriter, r *http.Request) {
	// Handle user login
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	user, exists := users[username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
	}
	if !checkPasswordHash(user.HashedPassword, password) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}
	sessionToken := generateSessionToken(32)
	csrfToken := generateSessionToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		HttpOnly: false,
		Expires:  time.Now().Add(24 * time.Hour),
	})
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprint(w, "User logged in successfully")

}
func logout(w http.ResponseWriter, r *http.Request) {
	// Handle user logout
	if err := Authorize(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: false,
	})
	username := r.FormValue("username")
	user := users[username]
	user.CSRFToken = ""
	user.SessionToken = ""
	users[username] = user
	fmt.Fprint(w, "User logged out successfully")

}
func protected(w http.ResponseWriter, r *http.Request) {
	// Handle protected resource access
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := Authorize(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := r.FormValue("username")
	fmt.Fprintf(w, "Welcome to the protected resource, %s!", username)
}
