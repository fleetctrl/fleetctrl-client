package consts

const (
	Version            = "0.4.0"
	Production         = true
	ServiceName        = "fleetctrl-client"
	ServiceDisplayName = "fleetctrl client"
	TargetDir          = `C:\Program Files\fleetctrl`
	ProgramDataDir     = `C:\ProgramData\fleetctrl`
	TargetExeName      = "client.exe"
	CompanyRegitryKey  = `SOFTWARE\WOW6432Node\fleetctrl`
	RegisteryRootKey   = `SOFTWARE\WOW6432Node\fleetctrl\client`
	MaxLogSize         = 20 * 1024 * 1024 // 20 MB
)
