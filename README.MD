# FleetCtrl Client (Windows)

Lightweight Windows client that runs as a service and synchronizes computer information (including RustDesk ID) with a FleetCtrl server.

## Prerequisites

- Windows 10/11
- Go 1.24+ (only if building from source)
- Run PowerShell or CMD as Administrator for install/uninstall

## Build

### Windows

Build the executable into the `bin` folder:

```
go build -o .\bin\fleetctrl-client.exe .\cmd\main\
```

## Install as a Windows Service

1. Open PowerShell as Administrator.
2. Build the binary (or use a prebuilt one) and run the installer command:

```
.\fleetctrl-client.exe install --token "<ENROLLMENT_TOKEN>" --url "https://your-server.example.com"
```

What this does:

- Copies itself to `C:\Program Files\fleetctrl\client.exe`.
- Creates a Windows service named `fleetctrl-client` (display name: `fleetctrl client`) that starts automatically under `LocalSystem`.
- Stores client data under `C:\ProgramData\fleetctrl\`.

Verify the service is running:

```
Get-Service fleetctrl-client
```

or

```
sc query fleetctrl-client
```

## Uninstall the Service

1. Open PowerShell as Administrator.
2. Run:

```
.\fleetctrl-client.exe remove
```

This stops and removes the `fleetctrl-client` service and attempts to clean up:

- `C:\Program Files\fleetctrl` (binary and logs)
- `C:\ProgramData\fleetctrl` (tokens and data)

## Logs

When running as a service, logs are written to:

```
C:\Program Files\fleetctrl\client.log
```

## Notes

- Ensure the provided server URL is reachable from the machine during installation.
- Installation and removal require Administrator privileges.
