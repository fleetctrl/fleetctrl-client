package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindProcesses(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	// Executable names are compared case-insensitively, like Get-Process does.
	pids, err := findProcesses(strings.ToUpper(filepath.Base(exe)))
	require.NoError(t, err)
	assert.Contains(t, pids, uint32(os.Getpid()))

	running, err := IsProcessRunning(filepath.Base(exe))
	require.NoError(t, err)
	assert.True(t, running)

	running, err = IsProcessRunning("fleetctrl-no-such-process.exe")
	require.NoError(t, err)
	assert.False(t, running)
}
