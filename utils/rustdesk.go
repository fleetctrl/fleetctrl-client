package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func GetRustDeskID() (string, error) {
	path := filepath.Join(os.Getenv("ProgramFiles"), "RustDesk", "rustdesk.exe")
	cmd := exec.Command(path, "--get-id")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("chyba při získávání ID: %v", err)
	}
	// Trim whitespace and convert to string
	output = []byte(string(output)[:len(output)-1]) // Remove the trailing newline character
	return string(output), nil
}
