package utils

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestPickUserSession(t *testing.T) {
	const console = 1
	tests := []struct {
		name     string
		sessions []userSession
		wantID   uint32
		wantOK   bool
	}{
		{
			name:   "nobody logged on",
			wantOK: false,
		},
		{
			name: "ignores services session and sessions without user",
			sessions: []userSession{
				{ID: 0, State: windows.WTSActive, User: "SYSTEM"},
				{ID: console, State: windows.WTSActive},
			},
			wantOK: false,
		},
		{
			name: "prefers console over remote desktop",
			sessions: []userSession{
				{ID: 2, State: windows.WTSActive, User: "remote"},
				{ID: console, State: windows.WTSActive, User: "local"},
			},
			wantID: console,
			wantOK: true,
		},
		{
			name: "uses remote desktop when console has no user",
			sessions: []userSession{
				{ID: 3, State: windows.WTSDisconnected, User: "switched"},
				{ID: 2, State: windows.WTSActive, User: "remote"},
			},
			wantID: 2,
			wantOK: true,
		},
		{
			name: "uses disconnected session when no session is active",
			sessions: []userSession{
				{ID: 4, State: windows.WTSConnected, User: "connecting"},
				{ID: 3, State: windows.WTSDisconnected, User: "switched"},
			},
			wantID: 3,
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := pickUserSession(tt.sessions, console)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantID, got.ID)
			}
		})
	}
}

func TestGetCurrentUser(t *testing.T) {
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil || sessionID == 0 {
		t.Skip("test does not run in a user session")
	}
	session, err := findUserSession()
	require.NoError(t, err)
	if session.ID != sessionID {
		t.Skipf("the user working at the computer is in session %d, the test runs in session %d", session.ID, sessionID)
	}

	user, err := GetCurrentUser()
	require.NoError(t, err)
	want := os.Getenv("USERDOMAIN") + `\` + os.Getenv("USERNAME")
	assert.True(t, strings.EqualFold(want, user), "got %q, want %q", user, want)
}
