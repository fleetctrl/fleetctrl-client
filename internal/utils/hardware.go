package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"KiskaLE/RustDesk-ID/internal/models"
)

// Query the Windows system volume, which need not be C:, and aggregate all CPUs.
const hardwareScript = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$system = Get-CimInstance Win32_ComputerSystem
$osInfo = Get-CimInstance Win32_OperatingSystem
$cpus = @(Get-CimInstance Win32_Processor)
$drive = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $osInfo.SystemDrive)
if (!$drive -or !$cpus.Count) { throw 'Hardware inventory is incomplete' }
[ordered]@{
  cpu_name = ($cpus.Name -join '; ').Trim()
  cpu_cores = [uint32](($cpus | Measure-Object NumberOfCores -Sum).Sum)
  cpu_logical_processors = [uint32](($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
  ram_bytes = [uint64]$system.TotalPhysicalMemory
  system_drive = [string]$drive.DeviceID
  system_drive_total_bytes = [uint64]$drive.Size
  system_drive_free_bytes = [uint64]$drive.FreeSpace
} | ConvertTo-Json -Compress
`

func GetComputerHardware(ctx context.Context) (*models.Hardware, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", hardwareScript).Output()
	if err != nil {
		return nil, fmt.Errorf("query Windows hardware: %w", err)
	}
	var hardware models.Hardware
	if err := json.Unmarshal(out, &hardware); err != nil {
		return nil, fmt.Errorf("decode Windows hardware: %w", err)
	}
	return &hardware, nil
}
