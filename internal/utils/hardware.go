package utils

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"KiskaLE/RustDesk-ID/internal/models"

	"github.com/StackExchange/wmi"
)

var driveLetterPattern = regexp.MustCompile(`^[A-Za-z]:$`)

type win32ComputerSystem struct {
	TotalPhysicalMemory uint64
}

type win32Processor struct {
	Name                      string
	NumberOfCores             uint32
	NumberOfLogicalProcessors uint32
}

type win32LogicalDisk struct {
	DeviceID  string
	Size      uint64
	FreeSpace uint64
}

// GetComputerHardware returns the CPUs, memory, and the volume Windows is
// installed on, which need not be C:.
func GetComputerHardware(ctx context.Context) (*models.Hardware, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("query Windows hardware: %w", err)
	}

	// WMI queries cannot be cancelled, so stop waiting for a stuck one.
	type result struct {
		hardware *models.Hardware
		err      error
	}
	done := make(chan result, 1)
	go func() {
		hardware, err := queryHardware()
		done <- result{hardware, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("query Windows hardware: %w", r.err)
		}
		return r.hardware, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("query Windows hardware: %w", ctx.Err())
	}
}

func queryHardware() (*models.Hardware, error) {
	var systems []win32ComputerSystem
	if err := wmi.Query("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem", &systems); err != nil {
		return nil, fmt.Errorf("Win32_ComputerSystem: %w", err)
	}
	osInfo, err := queryOperatingSystem()
	if err != nil {
		return nil, fmt.Errorf("Win32_OperatingSystem: %w", err)
	}
	var cpus []win32Processor
	if err := wmi.Query("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", &cpus); err != nil {
		return nil, fmt.Errorf("Win32_Processor: %w", err)
	}
	if !driveLetterPattern.MatchString(osInfo.SystemDrive) {
		return nil, fmt.Errorf("unexpected system drive %q", osInfo.SystemDrive)
	}
	var disks []win32LogicalDisk
	query := fmt.Sprintf("SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DeviceID = '%s'", osInfo.SystemDrive)
	if err := wmi.Query(query, &disks); err != nil {
		return nil, fmt.Errorf("Win32_LogicalDisk: %w", err)
	}
	if len(systems) == 0 || len(cpus) == 0 || len(disks) == 0 {
		return nil, errors.New("hardware inventory is incomplete")
	}
	return newHardware(systems[0], cpus, disks[0]), nil
}

// newHardware aggregates all CPUs of a multi-socket computer.
func newHardware(system win32ComputerSystem, cpus []win32Processor, disk win32LogicalDisk) *models.Hardware {
	hardware := &models.Hardware{
		RAMBytes:              system.TotalPhysicalMemory,
		SystemDrive:           disk.DeviceID,
		SystemDriveTotalBytes: disk.Size,
		SystemDriveFreeBytes:  disk.FreeSpace,
	}
	names := make([]string, 0, len(cpus))
	for _, cpu := range cpus {
		names = append(names, strings.TrimSpace(cpu.Name))
		hardware.CPUCores += cpu.NumberOfCores
		hardware.CPULogicalProcessors += cpu.NumberOfLogicalProcessors
	}
	hardware.CPUName = strings.Join(names, "; ")
	return hardware
}
