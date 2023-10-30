package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

var secretKey = []byte("my-mrandiw-secret")

type GenerateTokenResponse struct {
	Token   interface{} `json:"token"`
	Message string      `json:"message"`
	Status  bool        `json:"status"`
}

type VerifyTokenResponse struct {
	Username    interface{} `json:"username"`
	Email       interface{} `json:"email"`
	Expired     interface{} `json:"expired"`
	ExpiredDate time.Time   `json:"expired_date"`
	Message     string      `json:"message"`
	Status      bool        `json:"status"`
}

func generateTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Create a JWT claims object.
	claims := jwt.MapClaims{
		"username": "Andi Wibowo",
		"email":    "mrandiiw@gmail.com",
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	}

	// Create a new JWT token with the claims and sign it with the secret key.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		http.Error(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	tokenResp := GenerateTokenResponse{
		Token:   tokenString,
		Message: "Token is Generated",
		Status:  true,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokenResp)
}

func verifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		responseError(w, "Token missing in Authorization header", http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method and return the secret key.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secretKey, nil
	})

	if err != nil {
		responseError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		responseError(w, "Token is Not Valid", http.StatusBadRequest)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	expUnix := int64(claims["exp"].(float64))
	expTime := time.Unix(expUnix, 0)
	verify := VerifyTokenResponse{
		Username:    claims["username"],
		Email:       claims["email"],
		Expired:     claims["exp"],
		ExpiredDate: expTime,
		Message:     "Token is Valid",
		Status:      true,
	}

	// verify is valid
	if !ok {
		responseError(w, "Token is Not Valid", http.StatusBadRequest)
		return
	}

	responseSuccess(w, verify, http.StatusOK)
}

func responseSuccess(w http.ResponseWriter, verify interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(verify)
}

func responseError(w http.ResponseWriter, message string, statusCode int) {
	verify := VerifyTokenResponse{
		Message: message,
		Status:  false,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(verify)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/generate-token", generateTokenHandler).Methods("GET")
	r.HandleFunc("/verify-token", verifyTokenHandler).Methods("GET")

	http.Handle("/", r)

	fmt.Println("Server is running on :8080")
	http.ListenAndServe(":8080", nil)
}
