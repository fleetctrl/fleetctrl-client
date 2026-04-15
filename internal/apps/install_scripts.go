package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

	if script.Hash != "" {
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
	}

	cleanup := func() {
		os.Remove(localPath)
	}

	return localPath, tempDir, cleanup, nil
}

func executePowerShellScriptAsSystem(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
	psArgs := []string{
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", fmt.Sprintf("$ErrorActionPreference='Stop'; & '%s'; if ($LASTEXITCODE -ne $null) { exit [int]$LASTEXITCODE }", strings.ReplaceAll(scriptPath, "'", "''")),
	}

	cmd := exec.CommandContext(ctx, "powershell.exe", psArgs...)
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

func executePowerShellScriptAsUser(ctx context.Context, scriptPath, workDir string) (scriptExecutionResult, error) {
	currentUser, err := utils.GetCurrentUser()
	if err != nil || currentUser == "" {
		return scriptExecutionResult{}, fmt.Errorf("failed to get current logged in user: %v", err)
	}

	taskName := fmt.Sprintf("FleetCtrl_InstallScript_%d", time.Now().UnixNano())
	outputFile := filepath.Join(workDir, fmt.Sprintf("install_script_output_%d.txt", time.Now().UnixNano()))
	exitCodeFile := filepath.Join(workDir, fmt.Sprintf("install_script_exit_%d.txt", time.Now().UnixNano()))
	completionMarker := filepath.Join(workDir, fmt.Sprintf("install_script_done_%d.txt", time.Now().UnixNano()))
	defer os.Remove(outputFile)
	defer os.Remove(exitCodeFile)
	defer os.Remove(completionMarker)

	wrapperScript := fmt.Sprintf(`
$exitCode = 0
$ErrorActionPreference = 'Stop'
try {
    $output = & '%s' *>&1
    $output | Out-File -FilePath '%s' -Encoding UTF8
    if ($LASTEXITCODE -ne $null) {
        $exitCode = [int]$LASTEXITCODE
    }
} catch {
    $_ | Out-File -FilePath '%s' -Encoding UTF8
    $exitCode = 1
} finally {
    $exitCode | Out-File -FilePath '%s' -Encoding ASCII -NoNewline
    "done" | Out-File -FilePath '%s' -Encoding ASCII -NoNewline
}
exit $exitCode
`, strings.ReplaceAll(scriptPath, "'", "''"),
		strings.ReplaceAll(outputFile, "'", "''"),
		strings.ReplaceAll(outputFile, "'", "''"),
		strings.ReplaceAll(exitCodeFile, "'", "''"),
		strings.ReplaceAll(completionMarker, "'", "''"))

	wrapperPath := filepath.Join(workDir, fmt.Sprintf("install_script_wrapper_%d.ps1", time.Now().UnixNano()))
	if err := os.WriteFile(wrapperPath, []byte(wrapperScript), 0644); err != nil {
		return scriptExecutionResult{}, fmt.Errorf("failed to create wrapper script: %v", err)
	}
	defer os.Remove(wrapperPath)

	createTaskScript := fmt.Sprintf(`
$action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument '--headless powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%s"' -WorkingDirectory '%s'
$principal = New-ScheduledTaskPrincipal -UserId '%s' -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName '%s' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName '%s'
`, wrapperPath, workDir, currentUser, taskName, taskName)

	createCmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", createTaskScript)
	createOutput, err := createCmd.CombinedOutput()
	if err != nil {
		return scriptExecutionResult{}, fmt.Errorf("failed to create scheduled task: %v, output: %s", err, string(createOutput))
	}

	defer func() {
		cleanupCmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
			fmt.Sprintf("Unregister-ScheduledTask -TaskName '%s' -Confirm:$false -ErrorAction SilentlyContinue", taskName))
		cleanupCmd.Run()
	}()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return scriptExecutionResult{}, ctx.Err()
		case <-ticker.C:
			if _, err := os.Stat(completionMarker); err == nil {
				time.Sleep(100 * time.Millisecond)

				output, readErr := os.ReadFile(outputFile)
				if readErr != nil && !os.IsNotExist(readErr) {
					return scriptExecutionResult{}, fmt.Errorf("failed to read script output: %v", readErr)
				}

				exitCodeRaw, readErr := os.ReadFile(exitCodeFile)
				if readErr != nil {
					return scriptExecutionResult{}, fmt.Errorf("failed to read script exit code: %v", readErr)
				}

				exitCodeValue := strings.TrimSpace(string(exitCodeRaw))
				exitCode, parseErr := strconv.Atoi(exitCodeValue)
				if parseErr != nil {
					return scriptExecutionResult{}, fmt.Errorf("failed to parse script exit code %q: %v", exitCodeValue, parseErr)
				}

				return scriptExecutionResult{
					Output:   output,
					ExitCode: exitCode,
				}, nil
			}
		}
	}
}
