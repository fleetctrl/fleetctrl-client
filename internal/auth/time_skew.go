package auth

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var serverTimeProbeClient = &http.Client{
	Transport: &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
	},
	Timeout: 10 * time.Second,
}

type serverTimeState struct {
	mu         sync.Mutex
	serverSkew time.Duration
}

func (s *serverTimeState) currentIAT() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Add(-s.serverSkew)
}

func (s *serverTimeState) updateFromDateHeader(date string) {
	if date == "" {
		return
	}
	srvTime, err := http.ParseTime(date)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.serverSkew = time.Since(srvTime)
	s.mu.Unlock()
}

func (as *AuthService) currentDPoPIssuedAt() time.Time {
	return as.timeState.currentIAT()
}

func (as *AuthService) updateServerSkewFromDateHeader(date string) {
	as.timeState.updateFromDateHeader(date)
}

func (as *AuthService) syncServerSkew() {
	if as == nil || strings.TrimSpace(as.serverURL) == "" {
		return
	}

	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(as.serverURL, "/")+"/health", nil)
	if err != nil {
		return
	}

	resp, err := serverTimeProbeClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	as.updateServerSkewFromDateHeader(resp.Header.Get("Date"))
}
