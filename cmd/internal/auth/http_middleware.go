package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// AuthTransport is an http.RoundTripper that ensures Authorization and DPoP headers
// are present and valid. It refreshes tokens when close to expiry and retries once on 401.
type AuthTransport struct {
	Base      http.RoundTripper
	Tokens    *Tokens
	AS        *AuthService
	OnRefresh func(Tokens)

	mu sync.Mutex

	// local_time - server_time; used to adjust DPoP iat
	serverSkew time.Duration
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
	}
	http.DefaultClient.Transport = tr
	// Set a single global timeout to avoid per-call races
	http.DefaultClient.Timeout = 10 * time.Minute
}

func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	// Wait until server is online before attempting the request
	if err := t.waitForServerOnline(req.Context()); err != nil {
		return nil, err
	}

	// Snapshot tokens for this attempt
	at, rt := t.currentTokens()

	// Build request copy with auth headers
	req1 := cloneRequest(req)
	t.setAuthHeaders(req1, at)

	res, err := base.RoundTrip(req1)
	if err != nil {
		// If server didn't respond, wait until it's online and retry once
		if werr := t.waitForServerOnline(req.Context()); werr == nil {
			reqRetry := cloneRequest(req)
			if req.GetBody != nil {
				if b, gerr := req.GetBody(); gerr == nil {
					reqRetry.Body = b
				}
			}
			t.setAuthHeaders(reqRetry, at)
			return base.RoundTrip(reqRetry)
		}
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
		// If refresh failed, try recover flow once
		if rerr := t.RecoverLocked(req.Context()); rerr != nil {
			return nil, err
		}
	}

	// Retry with fresh token
	at, _ = t.currentTokens()
	req2 := cloneRequest(req)
	if req.GetBody != nil {
		// recreate body for retry
		b, _ := req.GetBody()
		req2.Body = b
	}
	t.setAuthHeaders(req2, at)
	return base.RoundTrip(req2)
}

// waitForServerOnline blocks until the server responds healthy, or context is canceled.
func (t *AuthTransport) waitForServerOnline(ctx context.Context) error {
	if t.AS == nil {
		return nil
	}
	backoff := 60 * time.Second
	healthURL := t.AS.serverUrl + "/health"
	client := &http.Client{Transport: t.Base, Timeout: 10 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if resp, err := client.Do(req); err == nil {
			if resp.StatusCode == http.StatusOK {
				// capture server time skew if Date header is present
				if date := resp.Header.Get("Date"); date != "" {
					if srvTime, perr := http.ParseTime(date); perr == nil {
						skew := time.Since(srvTime)
						t.mu.Lock()
						t.serverSkew = skew
						t.mu.Unlock()
					}
				}
				drainAndClose(resp.Body)
				return nil
			}
			drainAndClose(resp.Body)
		}
		log.Println("Server není dostupný. Zkouším znovu za", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (t *AuthTransport) currentTokens() (access, refresh string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Tokens == nil {
		return "", ""
	}
	return t.Tokens.AccessToken, t.Tokens.RefreshToken
}

func (t *AuthTransport) refreshLocked(refreshToken string) error {
	if t.AS == nil || t.Tokens == nil {
		return errors.New("auth transport not initialized")
	}

	// Read the latest refresh token under lock
	t.mu.Lock()
	rt := t.Tokens.RefreshToken
	t.mu.Unlock()

	nt, err := t.AS.RefreshTokens(rt)
	if err != nil {
		return err
	}
	// Update tokens under lock and copy callback
	t.mu.Lock()
	t.Tokens.AccessToken = nt.AccessToken
	t.Tokens.RefreshToken = nt.RefreshToken
	cb := t.OnRefresh
	t.mu.Unlock()
	// Invoke callback outside the lock
	if cb != nil {
		cb(nt)
	}
	return nil
}

// recoverLocked calls the /token/recover endpoint with DPoP proof to obtain fresh tokens.
func (t *AuthTransport) RecoverLocked(ctx context.Context) error {
	if t.AS == nil || t.Tokens == nil {
		return errors.New("auth transport not initialized")
	}

	// Construct recover request (POST, empty body) with DPoP only
	recoverURL := t.AS.serverUrl + "/token/recover"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, recoverURL, nil)
	if err != nil {
		return err
	}
	// Use server skew to avoid stale proofs
	skew := func() time.Duration { t.mu.Lock(); defer t.mu.Unlock(); return t.serverSkew }()
	iat := time.Now().Add(-skew)
	if dpop, derr := CreateDPoPAt(http.MethodPost, recoverURL, "", iat); derr == nil {
		req.Header.Set("DPoP", dpop)
	}

	client := &http.Client{Transport: t.Base, Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer drainAndClose(res.Body)
	if res.StatusCode != http.StatusOK {
		return errors.New("POST chyba pri obnoveni tokenu pres recover")
	}

	var payload struct {
		Tokens Tokens `json:"tokens"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return err
	}

	// Update tokens and notify callback
	t.mu.Lock()
	t.Tokens.AccessToken = payload.Tokens.AccessToken
	t.Tokens.RefreshToken = payload.Tokens.RefreshToken
	cb := t.OnRefresh
	t.mu.Unlock()
	if cb != nil {
		cb(payload.Tokens)
	}
	return nil
}

func (t *AuthTransport) setAuthHeaders(req *http.Request, accessToken string) {
	if accessToken == "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	// Adjust iat by observed server skew
	skew := func() time.Duration { t.mu.Lock(); defer t.mu.Unlock(); return t.serverSkew }()
	iat := time.Now().Add(-skew)
	if dpop, err := CreateDPoPAt(req.Method, req.URL.String(), accessToken, iat); err == nil {
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
