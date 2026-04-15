# FleetCtrl Client (Windows)

Lightweight Windows client that runs as a service and synchronizes computer information (including RustDesk ID) with a FleetCtrl server.

## Prerequisites

- Windows 10/11
- Go 1.24+ (only if building from source)
- Run PowerShell or CMD as Administrator for install/uninstall

## Build

### Windows (Executable)

Build the executable into the `bin` folder:

```
go build -o .\bin\fleetctrl-client.exe .\cmd\main\
```

### Windows (MSI Installer)

Requires [WiX Toolset v4](https://wixtoolset.org/) installed globally via `dotnet`.

1. Install WiX v4 and required extensions:
   ```
   wix extension add -g WixToolset.UI.wixext
   ```
2. Build the `.exe` first as shown above.
3. Build the `.msi` file:
   ```
   wix build installer/installer.wxs -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -d Version=<VERSION> -arch x64 -o bin/fleetctrl-client.msi
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
- Stores the FleetCtrl DeviceID in `HKLM\SOFTWARE\fleetctrl\client\DeviceID`.

Verify the service is running:

```
Get-Service fleetctrl-client
```

or

```
sc query fleetctrl-client
```

### Using MSI Installer

You can also use the `.msi` installer. If you run it interactively (double-click), an UI dialog will ask for your token and server URL.

To install silently from the command line, use public properties `ENROLL_TOKEN` and `SERVER_URL`:

```
msiexec /i .\bin\fleetctrl-client.msi /qn ENROLL_TOKEN="<ENROLLMENT_TOKEN>" SERVER_URL="https://your-server.example.com"
```

The MSI will automatically copy the executable, install the Windows Service, and save the settings.

## Uninstall the Service

1. Open PowerShell as Administrator.
2. Run:

```
.\fleetctrl-client.exe remove
```

This stops and removes the `fleetctrl-client` service and attempts to clean up:

- `C:\Program Files\fleetctrl` (binary and logs)
- `C:\ProgramData\fleetctrl` (tokens and data)

By default the uninstall keeps `HKLM\SOFTWARE\fleetctrl\client\DeviceID`, so a later reinstall can pair back to the same device record.
When the DeviceID is preserved, FleetCtrl also keeps the device private key in `C:\ProgramData\fleetctrl\certs\priv.jwk` so reinstall can prove possession of the original device identity.

To fully remove the device identity as well, run:

```
.\fleetctrl-client.exe remove --delete-device-id
```

### Uninstall using MSI

If you installed via `.msi`, you can uninstall seamlessly via "Add or Remove Programs" in Windows, or via command line:

```
msiexec /x .\bin\fleetctrl-client.msi /qn
```
This will automatically execute the cleanup operations.

Interactive MSI uninstall shows a checkbox to preserve the device data. Silent uninstall keeps the DeviceID by default; to fully remove it, pass:

```
msiexec /x .\bin\fleetctrl-client.msi /qn PRESERVE_DEVICE_DATA=0
```

## Logs

When running as a service, logs are written to:

```
C:\Program Files\fleetctrl\client.log
```

## Notes

- Ensure the provided server URL is reachable from the machine during installation.
- Installation and removal require Administrator privileges.
