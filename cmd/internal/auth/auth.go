package auth

import (
	consts "KiskaLE/RustDesk-ID/cmd/internal/const"
	"KiskaLE/RustDesk-ID/cmd/internal/utils"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/supabase-community/supabase-go"
)

type AuthService struct {
	client    *supabase.Client
	serverUrl string
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func NewAuthService(serverUrl string) *AuthService {
	return &AuthService{serverUrl: serverUrl}
}

func (as *AuthService) Enroll() (Tokens, error) {
	// check if registery key exists
	fingeprint := GetComputerFingerprint()

	// get PC name
	computerName, err := utils.GetComputerName()
	if err != nil {
		return Tokens{}, err
	}

	// check connection to server
	ping, err := utils.Ping(as.serverUrl)
	if err != nil {
		log.Printf("chyba při kontrole připojení k serveru: %v", err)
		return Tokens{}, err
	}
	for !ping {
		log.Println("Server není dostupný. Čekám 15 minut na další pokus...")
		time.Sleep(15 * time.Minute)
		ping, err = utils.Ping(as.serverUrl)
		if err != nil {
			log.Printf("chyba při kontrole připojení k serveru: %v", err)
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

	res, err := utils.Post(as.serverUrl+"/enroll", map[string]string{
		"name":             computerName,
		"fingerprint_hash": fingeprint,
		"jkt":              jkt,
	}, map[string]string{
		"Content-Type":     "application/json",
		"enrollment-token": "DFSDFSDf",
	})
	if err != nil {
		return Tokens{}, err
	}

	if res.StatusCode != 201 {
		return Tokens{}, errors.New("POST chyba pri registrace počítače")
	}

	type EnrollResponse struct {
		Tokens Tokens `json:"tokens"`
	}

	// TODO get jwk frm response
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

	active, err := utils.Ping(as.serverUrl)
	if err != nil {
		return false, err
	}

	// wait until server is active
	for !active {
		time.Sleep(15 * time.Minute)
		active, err = utils.Ping(as.serverUrl)
		if err != nil {
			return false, err
		}
	}
	res, err := utils.Get(as.serverUrl+"/enroll/"+fingerprint+"/is-enrolled", map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return false, err
	}
	if res.StatusCode != 200 {
		return false, nil
	}

	return true, nil
}

func (as *AuthService) RefreshTokens(refreshToken string) (Tokens, error) {
	type RefreshResponse struct {
		Tokens Tokens `json:"tokens"`
	}

	res, err := utils.Post(as.serverUrl+"/token/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return Tokens{}, err
	}

	if res.StatusCode != 200 {
		return Tokens{}, errors.New("POST chyba pri aktualizování tokenu")
	}

	var resTokens RefreshResponse
	if err := json.NewDecoder(res.Body).Decode(&resTokens); err != nil {
		return Tokens{}, err
	}

	return resTokens.Tokens, nil
}
