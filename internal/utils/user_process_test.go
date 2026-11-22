package utils

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// currentUserSession returns a session for the user running the test. Run
// works with any primary token; OpenUserSession needs LocalSystem.
func currentUserSession(t *testing.T) *UserSession {
	t.Helper()
	var token windows.Token
	access := uint32(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY)
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(), access, &token))
	session := &UserSession{token: token}
	t.Cleanup(func() { session.Close() })
	return session
}

func TestUserSessionRun(t *testing.T) {
	session := currentUserSession(t)
	cmd := os.Getenv("ComSpec")

	t.Run("returns separate output and exit code", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code, err := session.Run(context.Background(), []string{cmd, "/c", "echo out& echo err 1>&2& exit /b 3"}, &stdout, &stderr)
		require.NoError(t, err)
		assert.Equal(t, 3, code)
		assert.Equal(t, "out", strings.TrimSpace(stdout.String()))
		assert.Equal(t, "err", strings.TrimSpace(stderr.String()))
	})

	t.Run("combines output written to the same writer", func(t *testing.T) {
		var output bytes.Buffer
		code, err := session.Run(context.Background(), []string{cmd, "/c", "echo out& echo err 1>&2"}, &output, &output)
		require.NoError(t, err)
		assert.Equal(t, 0, code)
		assert.Contains(t, output.String(), "out")
		assert.Contains(t, output.String(), "err")
	})

	t.Run("discards output without writers", func(t *testing.T) {
		code, err := session.Run(context.Background(), []string{cmd, "/c", "echo out& exit /b 4"}, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, 4, code)
	})

	t.Run("starts in the user's profile directory with the user's environment", func(t *testing.T) {
		var stdout bytes.Buffer
		_, err := session.Run(context.Background(), []string{cmd, "/c", "cd& echo %USERPROFILE%"}, &stdout, nil)
		require.NoError(t, err)
		profile, err := session.token.GetUserProfileDirectory()
		require.NoError(t, err)
		lines := strings.FieldsFunc(stdout.String(), func(r rune) bool { return r == '\r' || r == '\n' })
		require.Len(t, lines, 2)
		assert.True(t, strings.EqualFold(profile, lines[0]), "working directory %q", lines[0])
		assert.True(t, strings.EqualFold(profile, lines[1]), "USERPROFILE %q", lines[1])
	})

	t.Run("terminates the program when the context ends", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ping := filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE")
		start := time.Now()
		_, err := session.Run(ctx, []string{ping, "-n", "30", "127.0.0.1"}, nil, nil)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, time.Since(start), 5*time.Second)
	})

	t.Run("does not wait for processes that keep the output open", func(t *testing.T) {
		original := outputWaitDelay
		outputWaitDelay = 200 * time.Millisecond
		defer func() { outputWaitDelay = original }()

		var stdout bytes.Buffer
		start := time.Now()
		code, err := session.Run(context.Background(), []string{cmd, "/c", "start /b ping -n 4 127.0.0.1& echo started"}, &stdout, &stdout)
		require.NoError(t, err)
		assert.Equal(t, 0, code)
		assert.Contains(t, stdout.String(), "started")
		assert.Less(t, time.Since(start), 2500*time.Millisecond)
	})

	t.Run("rejects empty command", func(t *testing.T) {
		_, err := session.Run(context.Background(), nil, nil, nil)
		assert.Error(t, err)
	})
}

// TestUserSessionRunScriptInInaccessibleDirectory reproduces how the service
// runs a script as the user: the script is in a directory that the user
// cannot open, like C:\Windows\SystemTemp, and GrantRead gives the user
// access to the script file alone.
func TestUserSessionRunScriptInInaccessibleDirectory(t *testing.T) {
	session := currentUserSession(t)
	user, err := session.token.GetTokenUser()
	require.NoError(t, err)
	userSID := user.User.Sid.String()

	dir := filepath.Join(t.TempDir(), "service-temp")
	require.NoError(t, os.Mkdir(dir, 0o700))
	script := filepath.Join(dir, "script.ps1")
	require.NoError(t, os.WriteFile(script, []byte("Write-Output \"user=$env:USERNAME\"\nexit 7\n"), 0o600))

	// Only SYSTEM and Administrators may open the directory, as in SystemTemp.
	setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true)
	t.Cleanup(func() {
		setDACL(t, dir, "D:(A;OICI;FA;;;"+userSID+")", false)
		setDACL(t, script, "D:(A;;FA;;;"+userSID+")", false)
	})

	run := func() (int, string) {
		var output bytes.Buffer
		args := []string{PowerShellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}
		code, err := session.Run(context.Background(), args, &output, &output)
		require.NoError(t, err)
		return code, output.String()
	}

	if session.token.IsElevated() {
		t.Log("elevated token can open the directory, skipping the check without access")
	} else {
		code, output := run()
		require.NotEqual(t, 7, code, "the user could run the script without access: %s", output)
	}

	require.NoError(t, session.GrantRead(script))
	code, output := run()
	assert.Equal(t, 7, code, output)
	assert.Contains(t, output, "user="+os.Getenv("USERNAME"))
}

func TestUserSessionGrantRead(t *testing.T) {
	session := currentUserSession(t)
	user, err := session.token.GetTokenUser()
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "script.ps1")
	require.NoError(t, os.WriteFile(file, []byte("exit 0"), 0o600))
	require.NoError(t, session.GrantRead(file))

	sd, err := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, granted to the user explicitly.
	assert.Contains(t, sd.String(), "(A;;0x1200a9;;;"+user.User.Sid.String()+")")
}

func TestUserSessionGrantReadMissingFile(t *testing.T) {
	session := currentUserSession(t)
	err := session.GrantRead(filepath.Join(t.TempDir(), "missing.ps1"))
	assert.True(t, errors.Is(err, windows.ERROR_FILE_NOT_FOUND), "got %v", err)
}

func setDACL(t *testing.T, path, sddl string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil))
}
