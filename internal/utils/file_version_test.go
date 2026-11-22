package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetFileVersionMatchesPowerShell checks that GetFileVersion returns the
// value that detection rules compared before, read by PowerShell.
func TestGetFileVersionMatchesPowerShell(t *testing.T) {
	system32 := filepath.Join(os.Getenv("SystemRoot"), "System32")
	for _, name := range []string{"kernel32.dll", "notepad.exe", "WindowsPowerShell\\v1.0\\powershell.exe"} {
		path := filepath.Join(system32, name)
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
				`(Get-Item -LiteralPath $env:FLEETCTRL_TEST_PATH).VersionInfo.FileVersion`)
			cmd.Env = append(os.Environ(), "FLEETCTRL_TEST_PATH="+path)
			out, err := cmd.Output()
			require.NoError(t, err)
			want := strings.TrimSpace(string(out))
			require.NotEmpty(t, want)

			got, err := GetFileVersion(path)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestGetFileVersionWithoutVersionResource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(path, []byte("no version here"), 0o600))
	_, err := GetFileVersion(path)
	assert.Error(t, err)

	_, err = GetFileVersion(filepath.Join(t.TempDir(), "missing.exe"))
	assert.Error(t, err)
}
