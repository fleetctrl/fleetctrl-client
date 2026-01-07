package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RequirementResult represents the result of a requirement check
type RequirementResult struct {
	RequirementID string
	Passed        bool
	Error         error
}

// CheckRequirements verifies all requirements for a release
// Returns true if all requirements pass, false otherwise
func CheckRequirements(release models.AssignedRelease, serverURL string) (bool, error) {
	if len(release.Requirements) == 0 {
		utils.Info("No requirements to check for this release")
		return true, nil
	}

	utils.Infof("Checking %d requirements before installation...", len(release.Requirements))

	for _, req := range release.Requirements {
		passed, err := checkSingleRequirement(req, serverURL)
		if err != nil {
			utils.Errorf("Requirement %s check failed with error: %v", req.ID, err)
			return false, fmt.Errorf("requirement %s failed: %v", req.ID, err)
		}
		if !passed {
			utils.Infof("Requirement %s not met, skipping installation", req.ID)
			return false, nil
		}
		utils.Infof("Requirement %s passed", req.ID)
	}

	utils.Info("All requirements passed")
	return true, nil
}

// checkSingleRequirement downloads and executes a single requirement script
func checkSingleRequirement(req models.ReleaseRequirement, serverURL string) (bool, error) {
	// Download requirement script
	downloadURL := fmt.Sprintf("%s/apps/requirement/download/%s", serverURL, req.ID)
	utils.Infof("Downloading requirement script from: %s", downloadURL)

	resp, err := utils.Get(downloadURL, map[string]string{})
	if err != nil {
		return false, fmt.Errorf("failed to download requirement script: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("failed to download requirement script: HTTP %d", resp.StatusCode)
	}

	// Create temp file for script
	tempDir := os.TempDir()
	scriptPath := filepath.Join(tempDir, fmt.Sprintf("requirement_%s.ps1", req.ID))

	f, err := os.Create(scriptPath)
	if err != nil {
		return false, fmt.Errorf("failed to create temp script file: %v", err)
	}

	if _, err = utils.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(scriptPath)
		return false, fmt.Errorf("failed to save requirement script: %v", err)
	}
	f.Close()
	defer os.Remove(scriptPath)

	// Verify hash if provided
	if req.Hash != "" {
		fileHash, err := utils.CalculateFileHash(scriptPath)
		if err != nil {
			return false, fmt.Errorf("failed to calculate hash: %v", err)
		}
		if !strings.EqualFold(fileHash, req.Hash) {
			return false, fmt.Errorf("hash mismatch: expected %s, got %s", req.Hash, fileHash)
		}
		utils.Info("Requirement script hash verified successfully")
	}

	// Execute requirement script with timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second // Default timeout: 60 seconds
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var output []byte

	if req.RunAsSystem {
		// Run directly as SYSTEM (service context)
		utils.Info("Running requirement script as SYSTEM")
		output, err = runScriptAsSystem(ctx, scriptPath, tempDir)
	} else {
		// Run as currently logged in user
		utils.Info("Running requirement script as current user")
		output, err = runScriptAsUser(ctx, scriptPath, tempDir)
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return false, fmt.Errorf("requirement script timed out after %v", timeout)
		}
		return false, fmt.Errorf("requirement script execution failed: %v", err)
	}

	// Parse output - expect "True" or "False"
	// Remove BOM (Byte Order Mark) that PowerShell adds with UTF-8 encoding
	result := string(output)
	result = strings.TrimPrefix(result, "\xef\xbb\xbf") // UTF-8 BOM
	result = strings.TrimPrefix(result, "\ufeff")       // UTF-16 BOM as UTF-8
	result = strings.TrimSpace(result)
	result = strings.ToLower(result)
	utils.Infof("Requirement script output (cleaned): %s", result)

	// Check for boolean result - use contains to handle any extra whitespace/characters
	if strings.Contains(result, "true") || result == "1" || strings.Contains(result, "yes") {
		return true, nil
	}
	if strings.Contains(result, "false") || result == "0" || strings.Contains(result, "no") {
		return false, nil
	}

	// Default: if exit code is 0 and output is not explicitly false, consider it passed
	utils.Infof("Requirement script output not recognized, defaulting to passed")
	return true, nil
}

// runScriptAsSystem runs a PowerShell script in SYSTEM context
func runScriptAsSystem(ctx context.Context, scriptPath, workDir string) ([]byte, error) {
	psArgs := []string{
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
	}

	cmd := exec.CommandContext(ctx, "powershell", psArgs...)
	cmd.Dir = workDir

	return cmd.Output()
}

// runScriptAsUser runs a PowerShell script as the currently logged in user
func runScriptAsUser(ctx context.Context, scriptPath, workDir string) ([]byte, error) {
	// Get the currently logged in user
	currentUser, err := utils.GetCurrentUser()
	if err != nil || currentUser == "" {
		return nil, fmt.Errorf("failed to get current logged in user: %v", err)
	}

	utils.Infof("Running requirement script as user: %s", currentUser)

	// Create a unique task name
	taskName := fmt.Sprintf("FleetCtrl_Requirement_%d", time.Now().UnixNano())

	// Create output file for capturing script result
	outputFile := filepath.Join(workDir, fmt.Sprintf("requirement_output_%d.txt", time.Now().UnixNano()))
	defer os.Remove(outputFile)

	// Create a completion marker file
	completionMarker := filepath.Join(workDir, fmt.Sprintf("requirement_done_%d.txt", time.Now().UnixNano()))
	defer os.Remove(completionMarker)

	// Wrap the script to capture output to a file and create completion marker
	wrapperScript := fmt.Sprintf(`
try {
    $result = & '%s'
    $result | Out-File -FilePath '%s' -Encoding UTF8 -NoNewline
} catch {
    "Error: $_" | Out-File -FilePath '%s' -Encoding UTF8 -NoNewline
} finally {
    "done" | Out-File -FilePath '%s' -Encoding UTF8 -NoNewline
}
`, strings.ReplaceAll(scriptPath, "'", "''"),
		strings.ReplaceAll(outputFile, "'", "''"),
		strings.ReplaceAll(outputFile, "'", "''"),
		strings.ReplaceAll(completionMarker, "'", "''"))

	wrapperPath := filepath.Join(workDir, fmt.Sprintf("wrapper_%d.ps1", time.Now().UnixNano()))
	if err := os.WriteFile(wrapperPath, []byte(wrapperScript), 0644); err != nil {
		return nil, fmt.Errorf("failed to create wrapper script: %v", err)
	}
	defer os.Remove(wrapperPath)

	// Create scheduled task to run as the logged in user (hidden using conhost --headless)
	createTaskScript := fmt.Sprintf(`
$action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument '--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%s"' -WorkingDirectory '%s'
$principal = New-ScheduledTaskPrincipal -UserId '%s' -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName '%s' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName '%s'
`, wrapperPath, workDir, currentUser, taskName, taskName)

	// Create and start the scheduled task
	createCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", createTaskScript)
	createOutput, err := createCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create scheduled task: %v, output: %s", err, string(createOutput))
	}

	// Ensure task is cleaned up
	defer func() {
		cleanupCmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
			fmt.Sprintf("Unregister-ScheduledTask -TaskName '%s' -Confirm:$false -ErrorAction SilentlyContinue", taskName))
		cleanupCmd.Run()
	}()

	// Wait for completion marker file to appear (indicates script finished)
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled while waiting for script completion")
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for requirement script to complete")
		case <-ticker.C:
			// Check if completion marker exists
			if _, err := os.Stat(completionMarker); err == nil {
				// Small delay to ensure output file is fully written
				time.Sleep(100 * time.Millisecond)

				// Read output from file
				output, err := os.ReadFile(outputFile)
				if err != nil {
					return nil, fmt.Errorf("failed to read script output: %v", err)
				}

				utils.Infof("User context script completed, output file content: %s", string(output))
				return output, nil
			}
		}
	}
}
