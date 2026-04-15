package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func restoreInstallScriptDeps() func() {
	originalDownload := downloadReleaseScriptFunc
	originalSystem := executePowerShellScriptAsSystemFunc
	originalUser := executePowerShellScriptAsUserFunc
	originalTempDir := tempDirFunc
	originalUUID := newUUIDFunc
	originalHTTPGet := httpGetFunc
	originalCopy := copyFunc
	originalHash := calculateFileHashFunc

	return func() {
		downloadReleaseScriptFunc = originalDownload
		executePowerShellScriptAsSystemFunc = originalSystem
		executePowerShellScriptAsUserFunc = originalUser
		tempDirFunc = originalTempDir
		newUUIDFunc = originalUUID
		httpGetFunc = originalHTTPGet
		copyFunc = originalCopy
		calculateFileHashFunc = originalHash
	}
}

func TestRunInstallScriptForPhase(t *testing.T) {
	t.Run("returns nil when phase is missing", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		called := false
		downloadReleaseScriptFunc = func(script models.ReleaseScript, serverURL string) (string, string, func(), error) {
			called = true
			return "", "", func() {}, nil
		}

		err := runInstallScriptForPhase(models.AssignedRelease{ID: "rel-1"}, "https://server", "before_install")
		require.NoError(t, err)
		assert.False(t, called)
	})

	t.Run("rejects unsupported engine", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		release := models.AssignedRelease{
			ID:      "rel-1",
			Scripts: []models.ReleaseScript{{ID: "script-1", Phase: "before_install", Engine: "bash"}},
		}

		err := runInstallScriptForPhase(release, "https://server", "before_install")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unsupported engine "bash"`)
	})

	t.Run("uses current user executor", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		cleanupCalled := false
		downloadReleaseScriptFunc = func(script models.ReleaseScript, serverURL string) (string, string, func(), error) {
			return "C:\\Temp\\script.ps1", "C:\\Temp", func() { cleanupCalled = true }, nil
		}

		systemCalled := false
		executePowerShellScriptAsSystemFunc = func(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
			systemCalled = true
			return scriptExecutionResult{}, nil
		}

		userCalled := false
		executePowerShellScriptAsUserFunc = func(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
			userCalled = true
			assert.Equal(t, "C:\\Temp\\script.ps1", scriptPath)
			assert.Equal(t, "C:\\Temp", workDir)
			return scriptExecutionResult{Output: []byte("ok"), ExitCode: 0}, nil
		}

		release := models.AssignedRelease{
			ID:      "rel-1",
			Scripts: []models.ReleaseScript{{ID: "script-1", Phase: "before_install", Engine: "powershell", ScriptName: "script.ps1"}},
		}

		require.NoError(t, runInstallScriptForPhase(release, "https://server", "before_install"))
		assert.True(t, userCalled)
		assert.False(t, systemCalled)
		assert.True(t, cleanupCalled)
	})

	t.Run("uses system executor when configured", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		downloadReleaseScriptFunc = func(script models.ReleaseScript, serverURL string) (string, string, func(), error) {
			return "C:\\Temp\\script.ps1", "C:\\Temp", func() {}, nil
		}

		systemCalled := false
		executePowerShellScriptAsSystemFunc = func(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
			systemCalled = true
			return scriptExecutionResult{ExitCode: 0}, nil
		}
		executePowerShellScriptAsUserFunc = func(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
			t.Fatal("did not expect user executor to be called")
			return scriptExecutionResult{}, nil
		}

		release := models.AssignedRelease{
			ID:      "rel-1",
			Scripts: []models.ReleaseScript{{ID: "script-1", Phase: "before_install", Engine: "powershell", ScriptName: "script.ps1", RunAsSystem: true}},
		}

		require.NoError(t, runInstallScriptForPhase(release, "https://server", "before_install"))
		assert.True(t, systemCalled)
	})

	t.Run("returns executor error", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		downloadReleaseScriptFunc = func(script models.ReleaseScript, serverURL string) (string, string, func(), error) {
			return "C:\\Temp\\script.ps1", "C:\\Temp", func() {}, nil
		}
		executePowerShellScriptAsUserFunc = func(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
			return scriptExecutionResult{}, errors.New("boom")
		}

		release := models.AssignedRelease{
			ID:      "rel-1",
			Scripts: []models.ReleaseScript{{ID: "script-1", Phase: "before_install", Engine: "powershell", ScriptName: "script.ps1"}},
		}

		err := runInstallScriptForPhase(release, "https://server", "before_install")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "execution failed: boom")
	})

	t.Run("returns non-zero exit code", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		downloadReleaseScriptFunc = func(script models.ReleaseScript, serverURL string) (string, string, func(), error) {
			return "C:\\Temp\\script.ps1", "C:\\Temp", func() {}, nil
		}
		executePowerShellScriptAsUserFunc = func(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
			return scriptExecutionResult{ExitCode: 12}, nil
		}

		release := models.AssignedRelease{
			ID:      "rel-1",
			Scripts: []models.ReleaseScript{{ID: "script-1", Phase: "before_install", Engine: "powershell", ScriptName: "script.ps1"}},
		}

		err := runInstallScriptForPhase(release, "https://server", "before_install")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exited with code 12")
	})

	t.Run("returns timeout error", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		downloadReleaseScriptFunc = func(script models.ReleaseScript, serverURL string) (string, string, func(), error) {
			return "C:\\Temp\\script.ps1", "C:\\Temp", func() {}, nil
		}
		executePowerShellScriptAsUserFunc = func(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
			<-ctx.Done()
			return scriptExecutionResult{}, ctx.Err()
		}

		release := models.AssignedRelease{
			ID:      "rel-1",
			Scripts: []models.ReleaseScript{{ID: "script-1", Phase: "before_install", Engine: "powershell", ScriptName: "script.ps1", TimeoutSeconds: 1}},
		}

		start := time.Now()
		err := runInstallScriptForPhase(release, "https://server", "before_install")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out after 1s")
		assert.GreaterOrEqual(t, time.Since(start), 900*time.Millisecond)
	})
}

func TestDownloadReleaseScript(t *testing.T) {
	t.Run("downloads and verifies script", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		tempDirFunc = t.TempDir
		newUUIDFunc = func() string { return "fixed-uuid" }
		body := []byte("Write-Host 'hello'")
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])

		httpGetFunc = func(url string, headers map[string]string) (*http.Response, error) {
			assert.Equal(t, "https://server/apps/script/download/script-1", url)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		}

		script := models.ReleaseScript{ID: "script-1", ScriptName: "install.ps1", ByteSize: int64(len(body)), Hash: hash}
		path, workDir, cleanup, err := downloadReleaseScript(script, "https://server")
		require.NoError(t, err)
		assert.Equal(t, filepath.Dir(path), workDir)
		assert.True(t, strings.HasSuffix(path, `script-1_fixed-uuid.ps1`))

		gotBody, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, body, gotBody)

		cleanup()
		_, err = os.Stat(path)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("fails on non-200 status", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		tempDirFunc = t.TempDir
		newUUIDFunc = func() string { return "fixed-uuid" }
		httpGetFunc = func(url string, headers map[string]string) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("bad gateway"))}, nil
		}

		_, _, _, err := downloadReleaseScript(models.ReleaseScript{ID: "script-1", ScriptName: "install.ps1"}, "https://server")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "download failed: HTTP 502")
	})

	t.Run("fails on size mismatch and removes file", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		tempDir := t.TempDir()
		tempDirFunc = func() string { return tempDir }
		newUUIDFunc = func() string { return "fixed-uuid" }
		httpGetFunc = func(url string, headers map[string]string) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("abc"))}, nil
		}

		path := filepath.Join(tempDir, "script-1_fixed-uuid.ps1")
		_, _, _, err := downloadReleaseScript(models.ReleaseScript{ID: "script-1", ScriptName: "install.ps1", ByteSize: 10}, "https://server")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "size mismatch")
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr))
	})

	t.Run("fails on hash mismatch and removes file", func(t *testing.T) {
		defer restoreInstallScriptDeps()()

		tempDir := t.TempDir()
		tempDirFunc = func() string { return tempDir }
		newUUIDFunc = func() string { return "fixed-uuid" }
		httpGetFunc = func(url string, headers map[string]string) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("abc"))}, nil
		}

		path := filepath.Join(tempDir, "script-1_fixed-uuid.ps1")
		_, _, _, err := downloadReleaseScript(models.ReleaseScript{ID: "script-1", ScriptName: "install.ps1", Hash: "deadbeef"}, "https://server")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hash mismatch")
		_, statErr := os.Stat(path)
		assert.True(t, os.IsNotExist(statErr))
	})
}
