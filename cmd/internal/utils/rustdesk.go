package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func GetRustDeskID() (string, error) {
	path := filepath.Join(os.Getenv("ProgramFiles"), "RustDesk", "rustdesk.exe")
	cmd := exec.Command(path, "--get-id")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("chyba při získávání ID: %v", err)
	}
	// Trim whitespace and convert to string
	id := strings.TrimSpace(string(output))
	return id, nil
}
