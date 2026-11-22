package utils

import (
	"errors"
	"net"
	"strings"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
)

// GetComputerName returns the NetBIOS name of the computer, the value of
// %COMPUTERNAME%.
func GetComputerName() (string, error) {
	return windows.ComputerName()
}

type win32OperatingSystem struct {
	Caption     string
	Version     string
	SystemDrive string
}

func queryOperatingSystem() (win32OperatingSystem, error) {
	var rows []win32OperatingSystem
	if err := wmi.Query("SELECT Caption, Version, SystemDrive FROM Win32_OperatingSystem", &rows); err != nil {
		return win32OperatingSystem{}, err
	}
	if len(rows) == 0 {
		return win32OperatingSystem{}, errors.New("Win32_OperatingSystem returned no instance")
	}
	return rows[0], nil
}

// GetComputerOS returns the name of the Windows edition, such as
// "Microsoft Windows 11 Pro".
func GetComputerOS() (string, error) {
	osInfo, err := queryOperatingSystem()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(osInfo.Caption), nil
}

// GetComputerOSVersion returns the Windows version, such as "10.0.26200".
func GetComputerOSVersion() (string, error) {
	osInfo, err := queryOperatingSystem()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(osInfo.Version), nil
}

// GetComputerIP returns the first private IPv4 address (10.0.0.0/8,
// 172.16.0.0/12 or 192.168.0.0/16) of a network adapter that is up, or an
// empty string if there is none.
func GetComputerIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if ip := firstPrivateIPv4(addrs); ip != "" {
			return ip, nil
		}
	}
	return "", nil
}

func firstPrivateIPv4(addrs []net.Addr) string {
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := ipNet.IP.To4(); ip != nil && ip.IsPrivate() {
			return ip.String()
		}
	}
	return ""
}
