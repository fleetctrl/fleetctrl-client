package auth

import (
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/utils"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/supabase-community/supabase-go"
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRecoveryFailed      = errors.New("token recovery failed")
)

type AuthService struct {
	client    *supabase.Client
	serverURL string
	timeState serverTimeState
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Enrollment struct {
	Tokens   Tokens
	DeviceID string
}

func NewAuthService(serverURL string) *AuthService {
	return &AuthService{serverURL: serverURL}
}

func (as *AuthService) Enroll(enrollToken string) (Enrollment, error) {
	// get PC name
	computerName, err := utils.GetComputerName()
	if err != nil {
		return Enrollment{}, err
	}

	enrollURL := as.serverURL + "/enroll"
	headers := map[string]string{
		"Content-Type":     "application/json",
		"enrollment-token": enrollToken,
	}
	payload := map[string]string{
		"name": computerName,
	}

	// check connection to server
	ping, err := utils.Ping(as.serverURL)
	if err != nil {
		log.Printf("error checking connection to server: %v", err)
		return Enrollment{}, err
	}
	for !ping {
		log.Println("Server is unreachable. Waiting 1 minute for next attempt...")
		time.Sleep(1 * time.Minute)
		ping, err = utils.Ping(as.serverURL)
		if err != nil {
			log.Printf("error checking connection to server: %v", err)
			return Enrollment{}, err
		}
	}

	keys, err := generateKeys()
	if err != nil {
		log.Fatal(err)
	}
	if err := savePrivJWK(keys.privKey, consts.ProgramDataDir+"/certs", "priv.jwk"); err != nil {
		return Enrollment{}, err
	}

	jkt, err := JKTFromJWK(keys.pubKey)
	if err != nil {
		return Enrollment{}, err
	}
	payload["jkt"] = jkt

	res, err := utils.Post(enrollURL, payload, headers)
	if err != nil {
		return Enrollment{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != 201 {
		return Enrollment{}, errors.New("POST error during computer registration")
	}

	type EnrollResponse struct {
		Tokens   Tokens `json:"tokens"`
		DeviceID string `json:"device_id"`
	}

	// TODO get jwk from response
	var jwk EnrollResponse
	if err := json.NewDecoder(res.Body).Decode(&jwk); err != nil {
		return Enrollment{}, err
	}

	return Enrollment{
		Tokens: Tokens{
			AccessToken:  jwk.Tokens.AccessToken,
			RefreshToken: jwk.Tokens.RefreshToken,
		},
		DeviceID: strings.TrimSpace(jwk.DeviceID),
	}, nil
}

func (as *AuthService) IsEnrolled(deviceID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return false, errors.New("missing device ID")
	}

	active, err := utils.Ping(as.serverURL)
	if err != nil {
		return false, err
	}

	if !active {
		return false, errors.New("server is not active")
	}

	res, err := utils.Get(as.serverURL+"/devices/"+deviceID+"/is-enrolled", map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false, nil
	}

	return true, nil
}

func (as *AuthService) RefreshTokens(refreshToken string) (Tokens, error) {
	type RefreshResponse struct {
		Tokens Tokens `json:"tokens"`
	}

	url := as.serverURL + "/token/refresh"
	as.syncServerSkew()
	dpop, _, err := CreateDPoPAtWithJTI("POST", url, "", as.currentDPoPIssuedAt())
	if err != nil {
		return Tokens{}, err
	}

	res, err := utils.Post(url, map[string]string{
		"refresh_token": refreshToken,
	}, map[string]string{
		"Content-Type": "application/json",
		"DPoP":         dpop,
	})
	if err != nil {
		return Tokens{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		if res.StatusCode == 401 {
			return Tokens{}, ErrInvalidRefreshToken
		}
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
	as.syncServerSkew()
	dpop, _, err := CreateDPoPAtWithJTI("POST", url, "", as.currentDPoPIssuedAt())
	if err != nil {
		return Tokens{}, err
	}

	res, err := utils.Post(url, map[string]string{}, map[string]string{
		"Content-Type": "application/json",
		"DPoP":         dpop,
	})
	if err != nil {
		return Tokens{}, err
	}
	defer res.Body.Close()

	utils.Error(res)

	if res.StatusCode != 200 {
		if res.StatusCode == 401 {
			return Tokens{}, ErrRecoveryFailed
		}
		return Tokens{}, errors.New("POST error during token recovery")
	}

	var payload RecoverResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return Tokens{}, err
	}
	return payload.Tokens, nil
}
