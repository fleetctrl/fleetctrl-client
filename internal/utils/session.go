package utils

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrNoUserSession means that no user is logged on to the computer.
var ErrNoUserSession = errors.New("no user is logged on")

var procWTSQuerySessionInformationW = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQuerySessionInformationW")

// WTS_INFO_CLASS values for WTSQuerySessionInformationW.
const (
	wtsUserName   = 5
	wtsDomainName = 7
)

// userSession is a Windows session that a user is logged on to.
type userSession struct {
	ID     uint32
	State  uint32
	User   string
	Domain string
}

// pickUserSession returns the session of the user working at the computer:
// the console session if a user is logged on there, otherwise another active
// session (Remote Desktop), otherwise a disconnected one (the user switched
// users or closed Remote Desktop without logging off).
func pickUserSession(sessions []userSession, consoleID uint32) (userSession, bool) {
	var best userSession
	bestRank := 0
	for _, s := range sessions {
		// Session 0 runs only services.
		if s.ID == 0 || s.User == "" {
			continue
		}
		rank := 0
		switch {
		case s.State == windows.WTSActive && s.ID == consoleID:
			rank = 3
		case s.State == windows.WTSActive:
			rank = 2
		case s.State == windows.WTSDisconnected:
			rank = 1
		}
		if rank > bestRank {
			best, bestRank = s, rank
		}
	}
	return best, bestRank > 0
}

// findUserSession returns the session of the user working at the computer, or
// ErrNoUserSession.
func findUserSession() (userSession, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return userSession{}, fmt.Errorf("enumerate sessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))

	sessions := make([]userSession, 0, count)
	for _, s := range unsafe.Slice(info, count) {
		if s.SessionID == 0 {
			continue
		}
		user, err := querySessionString(s.SessionID, wtsUserName)
		if err != nil || user == "" {
			continue
		}
		domain, _ := querySessionString(s.SessionID, wtsDomainName)
		sessions = append(sessions, userSession{ID: s.SessionID, State: s.State, User: user, Domain: domain})
	}

	session, ok := pickUserSession(sessions, windows.WTSGetActiveConsoleSessionId())
	if !ok {
		return userSession{}, ErrNoUserSession
	}
	return session, nil
}

func querySessionString(sessionID uint32, infoClass uintptr) (string, error) {
	var buf *uint16
	var size uint32
	r, _, err := procWTSQuerySessionInformationW.Call(
		0, // WTS_CURRENT_SERVER_HANDLE
		uintptr(sessionID),
		infoClass,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return "", err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf), nil
}

// GetCurrentUser returns the user working at the computer as DOMAIN\user, or
// an empty string if nobody is logged on.
func GetCurrentUser() (string, error) {
	session, err := findUserSession()
	if errors.Is(err, ErrNoUserSession) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return session.qualifiedUser(), nil
}

// qualifiedUser returns DOMAIN\user, or just the user without a domain.
func (s userSession) qualifiedUser() string {
	if s.Domain == "" {
		return s.User
	}
	return s.Domain + `\` + s.User
}
