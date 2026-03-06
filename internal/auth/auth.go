package auth

import (
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/utils"
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/supabase-community/supabase-go"
)

var ErrUnauthorized = errors.New("unauthorized request")

type AuthService struct {
	client    *supabase.Client
	serverURL string
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func NewAuthService(serverURL string) *AuthService {
	return &AuthService{serverURL: serverURL}
}

func (as *AuthService) Enroll(enrollToken string) (Tokens, error) {
	// check if registery key exists
	fingeprint := GetComputerFingerprint()

	// get PC name
	computerName, err := utils.GetComputerName()
	if err != nil {
		return Tokens{}, err
	}

	// check connection to server
	ping, err := utils.Ping(as.serverURL)
	if err != nil {
		log.Printf("error checking connection to server: %v", err)
		return Tokens{}, err
	}
	for !ping {
		log.Println("Server is unreachable. Waiting 1 minute for next attempt...")
		time.Sleep(1 * time.Minute)
		ping, err = utils.Ping(as.serverURL)
		if err != nil {
			log.Printf("error checking connection to server: %v", err)
			return Tokens{}, err
		}
	}

	keys, err := generateKeys()
	if err != nil {
		log.Fatal(err)
	}
	savePrivJWK(keys.privKey, consts.ProgramDataDir+"/certs", "priv.jwk")

	jkt, err := JKTFromJWK(keys.pubKey)
	if err != nil {
		return Tokens{}, err
	}

	payload, err := json.Marshal(map[string]string{
		"name":             computerName,
		"fingerprint_hash": fingeprint,
		"jkt":              jkt,
	})
	if err != nil {
		return Tokens{}, err
	}

	req, err := http.NewRequest("POST", as.serverURL+"/enroll", bytes.NewBuffer(payload))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("enrollment-token", enrollToken)

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return Tokens{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != 201 {
		return Tokens{}, errors.New("POST error during computer registration")
	}

	type EnrollResponse struct {
		Tokens Tokens `json:"tokens"`
	}

	// TODO get jwk from response
	var jwk EnrollResponse
	if err := json.NewDecoder(res.Body).Decode(&jwk); err != nil {
		return Tokens{}, err
	}

	tokens := Tokens{
		AccessToken:  jwk.Tokens.AccessToken,
		RefreshToken: jwk.Tokens.RefreshToken,
	}

	return tokens, nil
}

func (as *AuthService) IsEnrolled() (bool, error) {
	fingerprint := GetComputerFingerprint()

	active, err := utils.Ping(as.serverURL)
	if err != nil {
		return false, err
	}

	if !active {
		return false, errors.New("server is not active")
	}

	req, err := http.NewRequest("GET", as.serverURL+"/enroll/"+fingerprint+"/is-enrolled", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return false, nil
	}

	return true, nil
}

func doRequestWithBackoff(req *http.Request) (*http.Response, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var res *http.Response
	var err error

	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second
	maxRetries := 5

	for i := 0; i < maxRetries; i++ {
		if req.Body != nil && req.GetBody != nil {
			rc, _ := req.GetBody()
			req.Body = rc
		}

		res, err = client.Do(req)

		if err == nil && res.StatusCode < 500 {
			return res, nil
		}

		if res != nil {
			res.Body.Close()
		}

		if i < maxRetries-1 {
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	return res, err
}

func (as *AuthService) RefreshTokens(refreshToken string) (Tokens, error) {
	type RefreshResponse struct {
		Tokens Tokens `json:"tokens"`
	}

	payload, err := json.Marshal(map[string]string{
		"refresh_token": refreshToken,
	})
	if err != nil {
		return Tokens{}, err
	}

	req, err := http.NewRequest("POST", as.serverURL+"/token/refresh", bytes.NewBuffer(payload))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := doRequestWithBackoff(req)
	if err != nil {
		return Tokens{}, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return Tokens{}, ErrUnauthorized
	}

	if res.StatusCode != 200 {
		return Tokens{}, errors.New("POST error during token update")
	}

	var resTokens RefreshResponse
	if err := json.NewDecoder(res.Body).Decode(&resTokens); err != nil {
		return Tokens{}, err
	}

	return resTokens.Tokens, nil
}

// RecoverTokens calls /token/recover with a DPoP proof (no Authorization)
// and returns a fresh pair of access/refresh tokens.
func (as *AuthService) RecoverTokens() (Tokens, error) {
	type RecoverResponse struct {
		Tokens Tokens `json:"tokens"`
	}

	url := as.serverURL + "/token/recover"

	// Build DPoP for POST without access token (no auth)
	dpop, _, err := CreateDPoPAtWithJTI("POST", url, "", time.Now())
	if err != nil {
		return Tokens{}, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(`{}`)))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", dpop)

	res, err := doRequestWithBackoff(req)
	if err != nil {
		return Tokens{}, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return Tokens{}, ErrUnauthorized
	}

	if res.StatusCode != 200 {
		return Tokens{}, errors.New("POST error during token recovery")
	}

	var payload RecoverResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return Tokens{}, err
	}
	return payload.Tokens, nil
}
