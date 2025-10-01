package auth

import (
	consts "KiskaLE/RustDesk-ID/cmd/internal/const"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
	"github.com/billgraziano/dpapi"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type win32BaseBoard struct {
	SerialNumber *string
}
type win32BIOS struct {
	SerialNumber *string
}
type win32NetworkAdapter struct {
	MACAddress      *string
	PhysicalAdapter bool
	NetEnabled      *bool
}

type Keys struct {
	pubKey  *ecdsa.PublicKey
	privKey *ecdsa.PrivateKey
	kid     string
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func isJunk(s string) bool {
	v := strings.ToUpper(strings.TrimSpace(s))
	v = strings.ReplaceAll(v, " ", "")
	v = strings.ReplaceAll(v, ".", "")
	v = strings.ReplaceAll(v, "-", "")
	switch v {
	case "", "UNKNOWN", "NONE", "DEFAULTSTRING",
		"TOBEFILLEDBYOEM", "NOTSPECIFIED", "N/A":
		return true
	}
	return false
}

func baseboardSerial() string {
	var rows []win32BaseBoard
	if err := wmi.Query(
		"SELECT SerialNumber FROM Win32_BaseBoard", &rows,
	); err != nil {
		return ""
	}
	if len(rows) == 0 || rows[0].SerialNumber == nil {
		return ""
	}
	v := *rows[0].SerialNumber
	if isJunk(v) {
		return ""
	}
	return normalize(v)
}

func biosSerial() string {
	var rows []win32BIOS
	if err := wmi.Query(
		"SELECT SerialNumber FROM Win32_BIOS", &rows,
	); err != nil {
		return ""
	}
	if len(rows) == 0 || rows[0].SerialNumber == nil {
		return ""
	}
	v := *rows[0].SerialNumber
	if isJunk(v) {
		return ""
	}
	return normalize(v)
}

func physicalMACs() []string {
	var nics []win32NetworkAdapter
	if err := wmi.Query(
		"SELECT MACAddress, PhysicalAdapter, NetEnabled FROM "+
			"Win32_NetworkAdapter",
		&nics,
	); err != nil {
		return nil
	}
	out := make([]string, 0, len(nics))
	for _, n := range nics {
		if !n.PhysicalAdapter {
			continue
		}
		if n.NetEnabled == nil || !*n.NetEnabled {
			continue
		}
		if n.MACAddress == nil {
			continue
		}
		v := *n.MACAddress
		if isJunk(v) {
			continue
		}
		out = append(out, normalize(v))
	}
	// dedup + sort
	m := map[string]struct{}{}
	for _, v := range out {
		m[v] = struct{}{}
	}
	out = out[:0]
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func fingerprintBoardAndMAC(
	salt string,
	includeMAC bool,
	includeBIOS bool,
) (string, map[string]string) {
	parts := []string{}
	details := map[string]string{}

	if bb := baseboardSerial(); bb != "" {
		details["baseboard_serial"] = bb
		parts = append(parts, "baseboard="+bb)
	}
	if includeBIOS {
		if bs := biosSerial(); bs != "" {
			details["bios_serial"] = bs
			parts = append(parts, "bios="+bs)
		}
	}
	if includeMAC {
		macs := physicalMACs()
		if len(macs) > 0 {
			joined := strings.Join(macs, ",")
			details["macs"] = joined
			parts = append(parts, "macs="+joined)
		}
	}

	parts = append(parts, "salt="+normalize(salt))
	data := strings.Join(parts, "\n")
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:]), details
}

func GetComputerFingerprint() string {
	hash, _ := fingerprintBoardAndMAC("my-app-v1", false, false)

	return hash
}

// Auth
func generateKeys() (Keys, error) {
	// 1) Generate EC P-256 keypair (recommended for DPoP)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Keys{}, fmt.Errorf("generate key: %v", err)
	}

	// 2) Wrap into JWK (private)
	privJWK, err := jwk.FromRaw(privKey)
	if err != nil {
		return Keys{}, fmt.Errorf("wrap private key: %v", err)
	}
	// Set alg/usage hints (optional but nice to have)
	_ = privJWK.Set(jwk.AlgorithmKey, "ES256")
	_ = privJWK.Set(jwk.KeyUsageKey, "sig")

	// 3) Derive public JWK (what you'll put into DPoP header "jwk")
	pubKey := &privKey.PublicKey
	pubJWK, err := jwk.FromRaw(pubKey)
	if err != nil {
		return Keys{}, fmt.Errorf("wrap public key: %v", err)
	}
	_ = pubJWK.Set(jwk.AlgorithmKey, "ES256")
	_ = pubJWK.Set(jwk.KeyUsageKey, "sig")

	// 4) Compute RFC 7638 thumbprint as kid (common practice)
	thumb, err := pubJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return Keys{}, fmt.Errorf("thumbprint: %v", err)
	}
	kid := fmt.Sprintf("%x", thumb) // or base64url if you prefer
	_ = privJWK.Set(jwk.KeyIDKey, kid)
	_ = pubJWK.Set(jwk.KeyIDKey, kid)

	return Keys{pubKey: pubKey, privKey: privKey, kid: kid}, nil
}

func SaveRefershToken(refreshToken string, path string, fileName string) error {
	// check if folder exists, if not create it
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, 0755)
		if err != nil {
			return err
		}
	}
	// Encrypt with DPAPI - user scope (default)
	enc, err := dpapi.EncryptMachineLocal(refreshToken)
	if err != nil {
		return err
	}

	// Write file with restricted permissions force
	return os.WriteFile(path+"/"+fileName, []byte(enc), 0600)
}

func savePrivJWK(priv *ecdsa.PrivateKey, path string, fileName string) error {
	// check if folder exists, if not create it
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, 0755)
		if err != nil {
			return err
		}
	}
	key, err := jwk.FromRaw(priv)
	if err != nil {
		return err
	}

	_ = key.Set(jwk.AlgorithmKey, "ES256")
	_ = key.Set(jwk.KeyUsageKey, "sig")

	// Serializace do JSON (JWK)
	plainJSON, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return err
	}

	// Šifrování přes DPAPI (user scope)
	enc, err := dpapi.EncryptMachineLocal(string(plainJSON))
	if err != nil {
		return err
	}

	// Write file with restricted permissions
	return os.WriteFile(path+"/"+fileName, []byte(enc), 0600)
}

// CreateDPoP builds a DPoP proof for the given address using the current time and method GET.
// Prefer CreateDPoPWithMethod or CreateDPoPAt from new code paths.
func CreateDPoP(adress string, accessToken string) (string, error) {
	return CreateDPoPWithMethod("GET", adress, accessToken)
}

// CreateDPoPWithMethod builds a DPoP proof for the given HTTP method and address using the current time.
func CreateDPoPWithMethod(method string, adress string, accessToken string) (string, error) {
	s, _, err := CreateDPoPAtWithJTI(method, adress, accessToken, time.Now())
	return s, err
}

// CreateDPoPAt builds a DPoP proof with an explicit iat timestamp.
func CreateDPoPAt(method string, adress string, accessToken string, iat time.Time) (string, error) {
	s, _, err := CreateDPoPAtWithJTI(method, adress, accessToken, iat)
	return s, err
}

// CreateDPoPAtWithJTI builds a DPoP proof and also returns the jti used.
func CreateDPoPAtWithJTI(method string, adress string, accessToken string, iat time.Time) (string, string, error) {
	// Load private key generated during enroll
	priv, err := loadPrivJWK(consts.ProgramDataDir+"/certs", "priv.jwk")
	if err != nil {
		return "", "", err
	}
	// Prepare public JWK for header
	pubJWK, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}

	// Marshal to map for jwt header compatibility
	jwkBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return "", "", err
	}
	var jwkMap map[string]any
	if err := json.Unmarshal(jwkBytes, &jwkMap); err != nil {
		return "", "", err
	}
	// Compute ath if access token provided
	var ath string
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		ath = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	// Claims per RFC9449
	jti := uuid.NewString()
	claims := jwt.MapClaims{
		"htm": strings.ToUpper(method),
		"htu": adress,
		"iat": iat.Unix(),
		"jti": jti,
	}
	if ath != "" {
		claims["ath"] = ath
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwkMap
	s, err := token.SignedString(priv)
	if err != nil {
		return "", "", err
	}
	return s, jti, nil
}

func LoadRefreshToken(path string, fileName string) (string, error) {
	enc, err := os.ReadFile(path + "/" + fileName)
	if err != nil {
		return "", err
	}

	dec, err := dpapi.Decrypt(string(enc))
	if err != nil {
		return "", err
	}

	return dec, nil
}

func loadPrivJWK(dir, fileName string) (*ecdsa.PrivateKey, error) {
	cipher, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		return nil, err
	}

	plain, err := dpapi.Decrypt(string(cipher))
	if err != nil {
		return nil, err
	}

	// 1) Zkus single JWK
	if k, err := jwk.ParseKey([]byte(plain)); err == nil {
		var pk ecdsa.PrivateKey
		if err := k.Raw(&pk); err != nil {
			return nil, err
		}
		return &pk, nil
	}

	// 2) Zkus JWK Set
	set, err := jwk.Parse([]byte(plain))
	if err != nil {
		return nil, err
	}
	if set.Len() == 0 {
		return nil, errors.New("loadPrivJWK: empty JWK set")
	}

	// Vezmi první key (nebo si najdi podle parametrů)
	key, ok := set.Key(0)
	if !ok {
		return nil, errors.New("loadPrivJWK: failed to get key[0] from set")
	}

	var pk ecdsa.PrivateKey
	if err := key.Raw(&pk); err != nil {
		return nil, err
	}
	return &pk, nil
}

func JKTFromJWK(key *ecdsa.PublicKey) (string, error) {
	if key == nil {
		return "", errors.New("nil jwk.Key")
	}

	// Zajistíme čistě veřejný klíč (bez "d" apod.)
	pub, err := jwk.PublicKeyOf(key)
	if err != nil {
		return "", err
	}

	// V jwx/v2 je na klíči metoda Thumbprint(crypto.Hash).
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(thumb), nil
}
