package utils

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetComputerName(t *testing.T) {
	name, err := GetComputerName()
	require.NoError(t, err)
	assert.True(t, strings.EqualFold(os.Getenv("COMPUTERNAME"), name), "got %q", name)
}

func TestFirstPrivateIPv4(t *testing.T) {
	ipNet := func(cidr string) net.Addr {
		ip, network, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		network.IP = ip
		return network
	}
	tests := []struct {
		name  string
		addrs []net.Addr
		want  string
	}{
		{"none", nil, ""},
		{"public and link-local only", []net.Addr{ipNet("8.8.8.8/24"), ipNet("169.254.10.1/16")}, ""},
		{"IPv6 private is skipped", []net.Addr{ipNet("fd00::1/64"), ipNet("10.1.2.3/8")}, "10.1.2.3"},
		{"172.16.0.0/12 lower bound", []net.Addr{ipNet("172.16.0.5/16")}, "172.16.0.5"},
		{"172.32.0.0 is public", []net.Addr{ipNet("172.32.0.5/16"), ipNet("192.168.1.20/24")}, "192.168.1.20"},
		{"first private wins", []net.Addr{ipNet("192.168.1.20/24"), ipNet("10.0.0.2/8")}, "192.168.1.20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, firstPrivateIPv4(tt.addrs))
		})
	}
}

func TestNewHardwareAggregatesCPUs(t *testing.T) {
	hardware := newHardware(
		win32ComputerSystem{TotalPhysicalMemory: 64 << 30},
		[]win32Processor{
			{Name: "Intel(R) Xeon(R) Gold 6338   ", NumberOfCores: 32, NumberOfLogicalProcessors: 64},
			{Name: " Intel(R) Xeon(R) Gold 6338", NumberOfCores: 32, NumberOfLogicalProcessors: 64},
		},
		win32LogicalDisk{DeviceID: "D:", Size: 1 << 40, FreeSpace: 1 << 39},
	)
	assert.Equal(t, "Intel(R) Xeon(R) Gold 6338; Intel(R) Xeon(R) Gold 6338", hardware.CPUName)
	assert.Equal(t, uint32(64), hardware.CPUCores)
	assert.Equal(t, uint32(128), hardware.CPULogicalProcessors)
	assert.Equal(t, uint64(64<<30), hardware.RAMBytes)
	assert.Equal(t, "D:", hardware.SystemDrive)
	assert.Equal(t, uint64(1<<40), hardware.SystemDriveTotalBytes)
	assert.Equal(t, uint64(1<<39), hardware.SystemDriveFreeBytes)
}
