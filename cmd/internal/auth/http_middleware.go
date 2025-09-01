package auth

import (
    "encoding/base64"
    "encoding/json"
    "errors"
    "io"
    "net/http"
    "strings"
    "sync"
    "time"
    "crypto/tls"
)

// AuthTransport is an http.RoundTripper that ensures Authorization and DPoP headers
// are present and valid. It refreshes tokens when close to expiry and retries once on 401.
type AuthTransport struct {
    Base      http.RoundTripper
    Tokens    *Tokens
    AS        *AuthService
    OnRefresh func(Tokens)

    mu   sync.Mutex
    skew time.Duration
}

// InitHTTPClient configures http.DefaultClient to use AuthTransport.
// Pass current tokens and AuthService for refresh; OnRefresh is called when tokens rotate.
func InitHTTPClient(as *AuthService, tokens *Tokens, onRefresh func(Tokens)) {
    // Underlying transport with TLS verify disabled to match existing utils.Get/Put behavior.
    base := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
    tr := &AuthTransport{
        Base:      base,
        Tokens:    tokens,
        AS:        as,
        OnRefresh: onRefresh,
        skew:      60 * time.Second,
    }
    http.DefaultClient.Transport = tr
}

func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    base := t.Base
    if base == nil {
        base = http.DefaultTransport
    }

    // Ensure we have a valid token before sending
    if err := t.ensureValidToken(); err != nil {
        return nil, err
    }

    // Snapshot tokens for this attempt
    at, rt := t.currentTokens()

    // Build request copy with auth headers
    req1 := cloneRequest(req)
    setAuthHeaders(req1, at)

    res, err := base.RoundTrip(req1)
    if err != nil {
        return res, err
    }

    if res.StatusCode != http.StatusUnauthorized {
        return res, nil
    }

    // Potentially stale token – try one refresh and one retry if possible
    // Only retry if body is replayable or nil
    if req.Body != nil && req.GetBody == nil {
        return res, nil
    }

    // Drain and close the first response before retry
    drainAndClose(res.Body)

    if err := t.refreshLocked(rt); err != nil {
        return nil, err
    }

    // Retry with fresh token
    at, _ = t.currentTokens()
    req2 := cloneRequest(req)
    if req.GetBody != nil {
        // recreate body for retry
        b, _ := req.GetBody()
        req2.Body = b
    }
    setAuthHeaders(req2, at)
    return base.RoundTrip(req2)
}

func (t *AuthTransport) currentTokens() (access, refresh string) {
    // No lock needed: we only read simple fields; refreshLocked protects updates
    if t.Tokens == nil {
        return "", ""
    }
    return t.Tokens.AccessToken, t.Tokens.RefreshToken
}

func (t *AuthTransport) ensureValidToken() error {
    at, rt := t.currentTokens()
    // If empty, try refresh
    if at == "" {
        return t.refreshLocked(rt)
    }
    exp, err := extractJWTExp(at)
    if err != nil {
        // If we can't parse, proceed without refresh
        return nil
    }
    if time.Until(exp) <= t.skew {
        return t.refreshLocked(rt)
    }
    return nil
}

func (t *AuthTransport) refreshLocked(refreshToken string) error {
    if t.AS == nil || t.Tokens == nil {
        return errors.New("auth transport not initialized")
    }

    t.mu.Lock()
    defer t.mu.Unlock()

    // Re-check under lock to avoid duplicate refreshes
    if t.Tokens.AccessToken != "" {
        if exp, err := extractJWTExp(t.Tokens.AccessToken); err == nil {
            if time.Until(exp) > t.skew {
                return nil
            }
        }
    }

    nt, err := t.AS.RefreshTokens(refreshToken)
    if err != nil {
        return err
    }
    t.Tokens.AccessToken = nt.AccessToken
    t.Tokens.RefreshToken = nt.RefreshToken
    if t.OnRefresh != nil {
        t.OnRefresh(nt)
    }
    return nil
}

func setAuthHeaders(req *http.Request, accessToken string) {
    if accessToken == "" {
        return
    }
    req.Header.Set("Authorization", "Bearer "+accessToken)
    if dpop, err := CreateDPoP(req.URL.String(), accessToken); err == nil {
        req.Header.Set("DPoP", dpop)
    }
}

func cloneRequest(req *http.Request) *http.Request {
    // Clone preserves most fields; Header must be deep-copied
    r2 := req.Clone(req.Context())
    r2.Header = make(http.Header, len(req.Header))
    for k, vv := range req.Header {
        cp := make([]string, len(vv))
        copy(cp, vv)
        r2.Header[k] = cp
    }
    return r2
}

func drainAndClose(rc io.ReadCloser) {
    if rc == nil {
        return
    }
    io.Copy(io.Discard, rc)
    rc.Close()
}

// extractJWTExp parses the exp claim (as seconds since epoch) from a JWT without verifying the signature.
func extractJWTExp(token string) (time.Time, error) {
    parts := strings.Split(token, ".")
    if len(parts) < 2 {
        return time.Time{}, errors.New("invalid jwt format")
    }
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return time.Time{}, err
    }
    var claims struct {
        Exp int64 `json:"exp"`
    }
    if err := json.Unmarshal(payload, &claims); err != nil {
        return time.Time{}, err
    }
    if claims.Exp == 0 {
        return time.Time{}, errors.New("jwt has no exp")
    }
    return time.Unix(claims.Exp, 0), nil
}
