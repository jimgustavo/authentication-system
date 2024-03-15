package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	Roles     []string  `json:"roles"`
}
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("postgres", "postgres://tavito:mamacita@localhost:5432/authentication?sslmode=disable")
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping the database:", err)
	}
}

func main() {
	defer db.Close()

	router := mux.NewRouter()

	// Serve static files from the "static" directory
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	router.HandleFunc("/signup", SignupHandler).Methods("POST")
	router.HandleFunc("/login", LoginHandler).Methods("POST")
	router.HandleFunc("/profile", UserProfileHandler).Methods("GET")
	router.HandleFunc("/static/user_profile", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "user_profile.html")
	}).Methods("GET")
	router.HandleFunc("/users", UsersListHandler).Methods("GET")
	router.HandleFunc("/reset_password/{email}", ResetPasswordHandler).Methods("PUT")
	router.HandleFunc("/delete/{id}", DeleteUserHandler).Methods("DELETE")
	//router.HandleFunc("/assign-admin-role/{id}", AssignAdminRoleHandler).Methods("POST")

	log.Println("Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	//PROCESS:
	// Parse request body
	// Validate input
	// Hash password
	// Check for duplicate emails
	// Insert user into database
	// Return appropriate response

	// Parse request body
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if user.Email == "" || user.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Check for duplicate emails
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", user.Email).Scan(&count)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	// Insert user into database
	createdAt := time.Now()
	err = db.QueryRow("INSERT INTO users (email, password, created_at) VALUES ($1, $2, $3) RETURNING id", user.Email, user.Password, createdAt).Scan(&user.ID)
	if err != nil {
		http.Error(w, "Failed to insert user into database", http.StatusInternalServerError)
		return
	}
	user.CreatedAt = createdAt

	// Return appropriate response
	user.Password = "" // Remove password from response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	//PROCESS:
	// Parse request body
	// Authenticate user
	// If authentication succeeds, generate JWT
	// Return appropriate response

	// Parse request body
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Authenticate user
	authenticated, err := authenticateUser(user.Email, user.Password)
	if err != nil {
		http.Error(w, "Failed to authenticate user", http.StatusUnauthorized)
		return
	}
	if !authenticated {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// If authentication succeeds, generate JWT
	token, err := generateJWT(user.Email)
	if err != nil {
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	// Return appropriate response
	response := map[string]string{
		"token": token,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func authenticateUser(email, password string) (bool, error) {
	// Retrieve user from the database by email
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE email = $1", email).Scan(&storedPassword)
	if err != nil {
		return false, err
	}

	// Compare the stored password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		return false, nil
	}

	return true, nil
}

func generateJWT(email string) (string, error) {
	// Create the JWT claims
	claims := Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
		},
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte("your-secret-key")) // Replace "your-secret-key" with your actual secret key
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func UserProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Parse Authentication Token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization token missing", http.StatusUnauthorized)
		return
	}

	// Extract token string without the "Bearer " prefix
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify Authentication Token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil // Replace "your-secret-key" with your actual secret key
	})
	if err != nil {
		fmt.Println("Error parsing token:", err) // Print error for debugging
		http.Error(w, "Failed to parse token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Extract User Information
	email := claims.Email

	// Retrieve User Profile from Database
	userProfile, err := getUserProfile(email)
	if err != nil {
		http.Error(w, "Failed to retrieve user profile", http.StatusInternalServerError)
		return
	}

	// Fetch Data from External API
	externalAPIURL := "http://localhost:3000/orders"
	resp, err := http.Get(externalAPIURL)
	if err != nil {
		http.Error(w, "Failed to fetch data from external API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse JSON Response from External API
	var orders []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&orders); err != nil {
		http.Error(w, "Failed to parse JSON response from external API", http.StatusInternalServerError)
		return
	}

	// Response Formatting
	response := map[string]interface{}{
		"email":      userProfile.Email,
		"created_at": userProfile.CreatedAt.Format(time.RFC3339), // Example formatting, adjust as needed
		// Add other profile fields here
		"orders": orders, // Include data from external API
	}

	// Send Response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getUserProfile(email string) (*User, error) {
	query := "SELECT email, created_at FROM users WHERE email = $1"
	row := db.QueryRow(query, email)
	var userProfile User
	err := row.Scan(&userProfile.Email, &userProfile.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &userProfile, nil
}

func UsersListHandler(w http.ResponseWriter, r *http.Request) {
	// Query the database to fetch all users
	rows, err := db.Query("SELECT id, email, created_at FROM users")
	if err != nil {
		http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Iterate over the rows and store user information in a slice
	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.CreatedAt); err != nil {
			http.Error(w, "Failed to retrieve user information", http.StatusInternalServerError)
			return
		}
		// Append user to the slice
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Failed to iterate over users", http.StatusInternalServerError)
		return
	}

	// Return the list of users as JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(users); err != nil {
		http.Error(w, "Failed to encode users as JSON", http.StatusInternalServerError)
		return
	}
}

func ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Parse user email from the request URL
	params := mux.Vars(r)
	email := params["email"]

	// Parse request body
	var updateRequest struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	err := json.NewDecoder(r.Body).Decode(&updateRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Retrieve current user's password from the database
	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE email = $1", email).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Failed to retrieve user information", http.StatusInternalServerError)
		return
	}

	// Compare the stored password with the provided old password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(updateRequest.OldPassword))
	if err != nil {
		log.Println("Password comparison failed:", err)
		http.Error(w, "Invalid old password", http.StatusUnauthorized)
		return
	}

	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(updateRequest.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
		return
	}

	// Update user's password in the database
	_, err = db.Exec("UPDATE users SET password = $1 WHERE email = $2", hashedNewPassword, email)
	if err != nil {
		http.Error(w, "Failed to update user password", http.StatusInternalServerError)
		return
	}

	// Return success response with an empty JSON object
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Parse user ID from the request URL
	params := mux.Vars(r)
	userID := params["id"]

	// Delete user from the database
	_, err := db.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusOK)
}

func AssignAdminRoleHandler(w http.ResponseWriter, r *http.Request) {

}

/*
/////////////////////CURL commands to test the endpoints////////////////////////
Signup Endpoint (/signup):
curl -X POST http://localhost:8080/signup \
-H "Content-Type: application/json" \
-d '{
  "email": "test@example.com",
  "password": "password123",
  "roles": ["user"]
}'

Login Endpoint (/login):
curl -X POST http://localhost:8080/login \
-H "Content-Type: application/json" \
-d '{
  "email": "test@example.com",
  "password": "password123"
}'

{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJleHAiOjE3MTAzODUxNTl9.zk7qVQmQsxZNxA1JOZ_k5iyZlAvWqBpprR6H_jhkVFw"}


User Profile Endpoint (GET /profile):
curl -X GET http://localhost:8080/profile \
-H "Authorization: Bearer <your_jwt_token>"
curl -X GET http://localhost:8080/profile \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJleHAiOjE3MTAzODUxNTl9.zk7qVQmQsxZNxA1JOZ_k5iyZlAvWqBpprR6H_jhkVFw"


Users List Endpoint (GET /users):
curl -X GET http://localhost:8080/users


Update User Endpoint (PUT /update):
curl -X PUT -H "Content-Type: application/json" -d '{"old_password": "oldpassword", "new_password": "newpassword"}' http://localhost:8080/reset_password/<user_email_here>
curl -X PUT -H "Content-Type: application/json" -d '{"old_password": "mamasota", "new_password": "mamacita"}' http://localhost:8080/reset_password/jimgustavo1987@gmail.com

Delete User Endpoint (DELETE /delete):
curl -X DELETE http://localhost:8080/delete/<user_id_here>

Assign Admin Role Endpoint (POST /assign-admin-role):


/////////////////////POSTGRES DATABASE CONFIGURATION////////////////////////
# Init Postgres in bash
psql
# List databases
\l
# Create database
CREATE DATABASE authentication;
# Switch to orders database
\c authentication
# Check you path in UNIX bash
pwd
# Execute sql script
\i /Users/tavito/Documents/go/authentication-system/authentication.sql
# Delete database in case you need
DROP DATABASE authentication;
*/
