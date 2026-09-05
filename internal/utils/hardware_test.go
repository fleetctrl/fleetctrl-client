package utils

import (
	"context"
	"os"
	"testing"
)

func TestHardwareQueryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := GetComputerHardware(ctx); err == nil {
		t.Fatal("cancelled hardware query succeeded")
	}
}

func TestWindowsHardwareInventory(t *testing.T) {
	if os.Getenv("FLEETCTRL_TEST_HARDWARE") != "1" {
		t.Skip("set FLEETCTRL_TEST_HARDWARE=1 to query the local Windows hardware")
	}
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
