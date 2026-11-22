package utils

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsProcessRunning reports whether a process with the executable name, such
// as "winget.exe", is running.
func IsProcessRunning(exeName string) (bool, error) {
	pids, err := findProcesses(exeName)
	return len(pids) > 0, err
}

// KillProcesses terminates all processes with the executable name.
func KillProcesses(exeName string) error {
	pids, err := findProcesses(exeName)
	if err != nil {
		return err
	}
	var errs []error
	for _, pid := range pids {
		process, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
		if err != nil {
			errs = append(errs, fmt.Errorf("open process %d: %w", pid, err))
			continue
		}
		if err := windows.TerminateProcess(process, 1); err != nil {
			errs = append(errs, fmt.Errorf("terminate process %d: %w", pid, err))
		}
		windows.CloseHandle(process)
	}
	return errors.Join(errs...)
}

// findProcesses returns the IDs of processes with the executable name,
// compared case-insensitively.
func findProcesses(exeName string) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var pids []uint32
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), exeName) {
			pids = append(pids, entry.ProcessID)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return pids, fmt.Errorf("list processes: %w", err)
	}
	return pids, nil
}
