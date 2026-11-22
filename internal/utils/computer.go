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
	// get private IPv4 address (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
	cmd := exec.Command("powershell", "-Command", "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.*' -or $_.IPAddress -like '10.*' -or $_.IPAddress -match '^172\\.(1[6-9]|2[0-9]|3[01])\\.' }).IPAddress | Select-Object -First 1")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	//trim white space
	computerIP := strings.TrimSpace(string(out))

	return computerIP, nil
}
