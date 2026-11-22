package utils

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHardwareQueryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := GetComputerHardware(ctx); err == nil {
		t.Fatal("cancelled hardware query succeeded")
	}
}

func skipUnlessHardwareTest(t *testing.T) {
	t.Helper()
	if os.Getenv("FLEETCTRL_TEST_HARDWARE") != "1" {
		t.Skip("set FLEETCTRL_TEST_HARDWARE=1 to query the local Windows hardware")
	}
}

func TestWindowsHardwareInventory(t *testing.T) {
	skipUnlessHardwareTest(t)
	hardware, err := GetComputerHardware(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hardware.CPUName == "" || hardware.CPUCores == 0 || hardware.CPULogicalProcessors == 0 || hardware.RAMBytes == 0 {
		t.Fatalf("missing CPU or RAM information: %+v", hardware)
	}
	if len(hardware.SystemDrive) != 2 || hardware.SystemDriveTotalBytes == 0 || hardware.SystemDriveFreeBytes > hardware.SystemDriveTotalBytes {
		t.Fatalf("invalid system volume information: %+v", hardware)
	}
}

// TestComputerInfoMatchesPowerShell compares the native queries with the
// PowerShell commands that the client used before.
func TestComputerInfoMatchesPowerShell(t *testing.T) {
	skipUnlessHardwareTest(t)
	powershell := func(command string) string {
		t.Helper()
		out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command).Output()
		require.NoError(t, err, command)
		return strings.TrimSpace(string(out))
	}

	osName, err := GetComputerOS()
	require.NoError(t, err)
	assert.Equal(t, powershell("(Get-CimInstance Win32_OperatingSystem).Caption"), osName)

	osVersion, err := GetComputerOSVersion()
	require.NoError(t, err)
	assert.Equal(t, powershell("(Get-CimInstance Win32_OperatingSystem).Version"), osVersion)

	name, err := GetComputerName()
	require.NoError(t, err)
	assert.Equal(t, powershell("$env:computername"), name)

	if consoleUser := powershell("(Get-CimInstance -ClassName Win32_ComputerSystem).Username"); consoleUser != "" {
		user, err := GetCurrentUser()
		require.NoError(t, err)
		assert.True(t, strings.EqualFold(consoleUser, user), "got %q, want %q", user, consoleUser)
	}

	ip, err := GetComputerIP()
	require.NoError(t, err)
	privateIPs := powershell("(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.*' -or $_.IPAddress -like '10.*' -or $_.IPAddress -match '^172\\.(1[6-9]|2[0-9]|3[01])\\.' }).IPAddress")
	if privateIPs != "" {
		assert.Contains(t, strings.Fields(privateIPs), ip)
	}

	hardware, err := GetComputerHardware(context.Background())
	require.NoError(t, err)
	var want struct {
		RAMBytes  uint64 `json:"ram"`
		Cores     uint32 `json:"cores"`
		Logical   uint32 `json:"logical"`
		Drive     string `json:"drive"`
		DriveSize uint64 `json:"size"`
	}
	require.NoError(t, json.Unmarshal([]byte(powershell(`
$os = Get-CimInstance Win32_OperatingSystem
$cpus = @(Get-CimInstance Win32_Processor)
$drive = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $os.SystemDrive)
@{
  ram = [uint64](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
  cores = [uint32](($cpus | Measure-Object NumberOfCores -Sum).Sum)
  logical = [uint32](($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
  drive = [string]$drive.DeviceID
  size = [uint64]$drive.Size
} | ConvertTo-Json -Compress`)), &want))
	assert.Equal(t, want.RAMBytes, hardware.RAMBytes)
	assert.Equal(t, want.Cores, hardware.CPUCores)
	assert.Equal(t, want.Logical, hardware.CPULogicalProcessors)
	assert.Equal(t, want.Drive, hardware.SystemDrive)
	assert.Equal(t, want.DriveSize, hardware.SystemDriveTotalBytes)
}
