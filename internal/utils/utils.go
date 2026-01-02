package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

type HttpError struct {
	Error string `json:"error"`
}

// ParseJSON reads the request body as JSON and decodes it into the provided value.
// It returns an error if the request body is missing or if the JSON decoding fails.
func ParseJSON(r *http.Request, payload any) error {
	if r.Body == nil {
		return fmt.Errorf("missing request body")
	}
	return json.NewDecoder(r.Body).Decode(payload)
}

func ParseHttpError(r *http.Response) string {
	var httpError HttpError
	if err := json.NewDecoder(r.Body).Decode(&httpError); err != nil {
		return ""
	}
	return httpError.Error
}

// WriteJSON writes a JSON response with the provided HTTP status code.
// It accepts an http.ResponseWriter to write the response, an integer status code, and a value of any type to be encoded as JSON.
// The function sets the "Content-Type" header to "application/json" and returns an error if JSON encoding fails.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// WriteError writes an error message as a JSON response with the provided HTTP status code.
// It accepts an http.ResponseWriter to write the response, an integer status code, and an error object.
// The function returns an error if the JSON encoding fails.
func WriteError(w http.ResponseWriter, status int, err error) error {
	return WriteJSON(w, status, map[string]string{"error": err.Error()})
}

func LoadEnv() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func Ping(host string) (bool, error) {
	res, err := Get(host+"/health", map[string]string{})
	if err != nil {
		return false, err
	}
	if res.StatusCode != 200 {
		return false, nil
	}
	return true, nil
}

// CalculateFileHash calculates the SHA256 hash of a file
func CalculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %v", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
