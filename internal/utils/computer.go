package utils

import (
	"os/exec"
	"strings"
)

func GetComputerName() (string, error) {
	// get computer name
	cmd := exec.Command("powershell", "-Command", "$env:computername")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	//trim white space
	computerName := strings.TrimSpace(string(out))
	return computerName, nil
}

func GetComputerOS() (string, error) {
	// get computer name
	cmd := exec.Command("powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).Caption")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	//trim white space
	computerOS := strings.TrimSpace(string(out))

	return computerOS, nil
}

func GetComputerOSVersion() (string, error) {
	// get computer name
	cmd := exec.Command("powershell", "-Command", "(Get-WmiObject Win32_OperatingSystem).Version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	//trim white space
	computerOSVersion := strings.TrimSpace(string(out))

	return computerOSVersion, nil
}

func GetComputerIP() (string, error) {
	// get computer name
	cmd := exec.Command("powershell", "-Command", "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.*.*' }).IPAddress | Select-Object -First 1")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	//trim white space
	computerIP := strings.TrimSpace(string(out))

	return computerIP, nil
}

func GetCurrentUser() (string, error) {
	// Method 1: Try Win32_ComputerSystem (works for domain users)
	cmd := exec.Command("powershell", "-Command", "(Get-CimInstance -ClassName Win32_ComputerSystem).Username")
	out, err := cmd.Output()
	if err == nil {
		user := strings.TrimSpace(string(out))
		if user != "" {
			return user, nil
		}
	}

	// Method 2: Try quser.exe (query user) - works for local and domain users
	cmd = exec.Command("powershell", "-Command", `
$quserOutput = quser 2>$null
if ($quserOutput) {
    $lines = $quserOutput | Select-Object -Skip 1
    foreach ($line in $lines) {
        if ($line -match 'Active') {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Count -gt 0) {
                Write-Output $parts[0]
                break
            }
        }
    }
}
`)
	out, err = cmd.Output()
	if err == nil {
		user := strings.TrimSpace(string(out))
		if user != "" {
			// Remove leading '>' if present
			user = strings.TrimPrefix(user, ">")
			return user, nil
		}
	}

	// Method 3: Get owner of explorer.exe process (most reliable fallback)
	cmd = exec.Command("powershell", "-Command", `
$explorer = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
if ($explorer) {
    $owner = $explorer.GetOwner()
    if ($owner.Domain) {
        Write-Output "$($owner.Domain)\$($owner.User)"
    } else {
        Write-Output $owner.User
    }
}
`)
	out, err = cmd.Output()
	if err == nil {
		user := strings.TrimSpace(string(out))
		if user != "" {
			return user, nil
		}
	}

	return "", nil
}
