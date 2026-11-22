package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultInstallScriptTimeout = 300 * time.Second

var (
	downloadReleaseScriptFunc           = downloadReleaseScript
	executePowerShellScriptAsSystemFunc = executePowerShellScriptAsSystem
	executePowerShellScriptAsUserFunc   = executePowerShellScriptAsUser
	tempDirFunc                         = os.TempDir
	newUUIDFunc                         = func() string { return uuid.New().String() }
	httpGetFunc                         = func(url string, headers map[string]string) (*http.Response, error) { return utils.Get(url, headers) }
	copyFunc                            = utils.Copy
	calculateFileHashFunc               = utils.CalculateFileHash
)

type scriptExecutionResult struct {
	Output   []byte
	ExitCode int
}

func runInstallScriptForPhase(release models.AssignedRelease, serverURL, phase string) error {
	script := findReleaseScriptByPhase(release.Scripts, phase)
	if script == nil {
		utils.Infof("No %s-install script configured for release %s", phase, release.ID)
		return nil
	}

	if !strings.EqualFold(script.Engine, "powershell") {
		return fmt.Errorf("%s-install script %s has unsupported engine %q", phase, script.ID, script.Engine)
	}

	scriptPath, workDir, cleanup, err := downloadReleaseScriptFunc(*script, serverURL)
	if err != nil {
		return fmt.Errorf("failed to download %s-install script: %v", phase, err)
	}
	defer cleanup()

	timeout := time.Duration(script.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultInstallScriptTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result scriptExecutionResult
	if script.RunAsSystem {
		utils.Infof("Running %s-install script %s as SYSTEM", phase, script.ScriptName)
		result, err = executePowerShellScriptAsSystemFunc(ctx, scriptPath, workDir)
	} else {
		utils.Infof("Running %s-install script %s as current user", phase, script.ScriptName)
		result, err = executePowerShellScriptAsUserFunc(ctx, scriptPath, workDir)
	}

	output := strings.TrimSpace(string(result.Output))
	if output != "" {
		utils.Infof("%s-install script output: %s", phase, output)
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s-install script timed out after %v", phase, timeout)
		}
		return fmt.Errorf("%s-install script execution failed: %v", phase, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("%s-install script exited with code %d", phase, result.ExitCode)
	}

	utils.Infof("%s-install script completed successfully", phase)
	return nil
}

func findReleaseScriptByPhase(scripts []models.ReleaseScript, phase string) *models.ReleaseScript {
	for i := range scripts {
		if strings.EqualFold(scripts[i].Phase, phase) {
			return &scripts[i]
		}
	}
	return nil
}

func downloadReleaseScript(script models.ReleaseScript, serverURL string) (string, string, func(), error) {
	tempDir := tempDirFunc()
	ext := strings.ToLower(filepath.Ext(script.ScriptName))
	if ext == "" {
		ext = ".ps1"
	}

	localPath := filepath.Join(tempDir, fmt.Sprintf("%s_%s%s", script.ID, newUUIDFunc(), ext))
	downloadURL := fmt.Sprintf("%s/apps/script/download/%s", serverURL, script.ID)
	utils.Infof("Downloading install script from: %s", downloadURL)

	resp, err := httpGetFunc(downloadURL, map[string]string{})
	if err != nil {
		return "", "", nil, fmt.Errorf("download request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", nil, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	file, err := os.Create(localPath)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create local script file: %v", err)
	}

	if _, err = copyFunc(file, resp.Body); err != nil {
		file.Close()
		os.Remove(localPath)
		return "", "", nil, fmt.Errorf("failed to save script: %v", err)
	}
	file.Close()

	if script.ByteSize > 0 {
		fileInfo, err := os.Stat(localPath)
		if err != nil {
			os.Remove(localPath)
			return "", "", nil, fmt.Errorf("failed to stat downloaded script: %v", err)
		}
		if fileInfo.Size() != script.ByteSize {
			os.Remove(localPath)
			return "", "", nil, fmt.Errorf("size mismatch: expected %d bytes, got %d bytes", script.ByteSize, fileInfo.Size())
		}
	}

	fileHash, err := calculateFileHashFunc(localPath)
	if err != nil {
		os.Remove(localPath)
		return "", "", nil, fmt.Errorf("failed to calculate hash: %v", err)
	}
	if !strings.EqualFold(fileHash, script.Hash) {
		os.Remove(localPath)
		return "", "", nil, fmt.Errorf("hash mismatch: expected %s, got %s", script.Hash, fileHash)
	}
	utils.Infof("Install script %s hash verified successfully", script.ScriptName)

	cleanup := func() {
		os.Remove(localPath)
	}

	return localPath, tempDir, cleanup, nil
}

// powerShellScriptArgs runs the script and exits with its exit code. A
// terminating error in the script makes PowerShell exit with code 1.
func powerShellScriptArgs(scriptPath string) []string {
	return []string{
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", fmt.Sprintf("$ErrorActionPreference='Stop'; & '%s'; if ($LASTEXITCODE -ne $null) { exit [int]$LASTEXITCODE }", strings.ReplaceAll(scriptPath, "'", "''")),
	}
}

func executePowerShellScriptAsSystem(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", powerShellScriptArgs(scriptPath)...)
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return scriptExecutionResult{
				Output:   output,
				ExitCode: exitErr.ExitCode(),
			}, nil
		}
		return scriptExecutionResult{Output: output}, err
	}

	return scriptExecutionResult{
		Output:   output,
		ExitCode: 0,
	}, nil
}

// executePowerShellScriptAsUser runs the script as the user working at the
// computer. The script stays in the service's temp directory, which the user
// cannot open, so the user gets read access to the script file alone, and the
// script starts in the user's profile directory instead of workDir.
func executePowerShellScriptAsUser(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
	session, err := utils.OpenUserSession()
	if err != nil {
		return scriptExecutionResult{}, fmt.Errorf("failed to open session of logged on user: %v", err)
	}
	defer session.Close()
	utils.Infof("Running install script as user %s (session %d)", session.User, session.ID)

	if err := session.GrantRead(scriptPath); err != nil {
		return scriptExecutionResult{}, fmt.Errorf("failed to give the user access to the script: %v", err)
	}

	var output bytes.Buffer
	args := append([]string{utils.PowerShellPath()}, powerShellScriptArgs(scriptPath)...)
	exitCode, err := session.Run(ctx, args, &output, &output)
	if err != nil {
		return scriptExecutionResult{Output: output.Bytes()}, err
	}
	return scriptExecutionResult{Output: output.Bytes(), ExitCode: exitCode}, nil
}
