package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
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
	scriptPath := filepath.Join(tempDir, fmt.Sprintf("%s.ps1", uuid.New().String()))

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
		output, err = runScriptAsUser(ctx, scriptPath)
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

// runScriptAsUser runs a PowerShell script as the user working at the
// computer and returns its standard output. The script stays in the service's
// temp directory, which the user cannot open, so the user gets read access to
// the script file alone.
func runScriptAsUser(ctx context.Context, scriptPath string) ([]byte, error) {
	session, err := utils.OpenUserSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open session of logged on user: %v", err)
	}
	defer session.Close()
	utils.Infof("Running requirement script as user %s (session %d)", session.User, session.ID)

	if err := session.GrantRead(scriptPath); err != nil {
		return nil, fmt.Errorf("failed to give the user access to the script: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{utils.PowerShellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath}
	exitCode, err := session.Run(ctx, args, &stdout, &stderr)
	if err != nil {
		return nil, err
	}
	if exitCode != 0 {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("exit status %d: %s", exitCode, msg)
		}
		return nil, fmt.Errorf("exit status %d", exitCode)
	}
	return stdout.Bytes(), nil
}
