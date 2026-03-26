package consts

import "time"

const (
	Version            = "1.2.0"
	Production         = true
	ServiceName        = "fleetctrl-client"
	ServiceDisplayName = "fleetctrl client"
	TargetDir          = `C:\Program Files\fleetctrl`
	ProgramDataDir     = `C:\ProgramData\fleetctrl`
	TargetExeName      = "client.exe"
	CompanyRegitryKey  = `SOFTWARE\fleetctrl`
	RegisteryRootKey   = `SOFTWARE\fleetctrl\client`
	DeviceIDValueName  = "DeviceID"
	MaxLogSize         = 20 * 1024 * 1024 // 20 MB
	AppInstallTimeout  = 30 * time.Minute
)
