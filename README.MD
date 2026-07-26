# FleetCtrl Client for Windows

FleetCtrl Client consists of two programs:

- `fleetctrl-client.exe` – a Windows service that communicates with the FleetCtrl server.
- `fleetctrl-ui.exe` – a local desktop application for monitoring the service.

The MSI package is recommended for standard installations. It installs both
programs, registers the service, and creates a **FleetCtrl** shortcut in the
Start menu.

## Build Requirements

Build the client on 64-bit Windows 10 or Windows 11.

- [Go 1.25 or later](https://go.dev/dl/)
- [Node.js 20 or later](https://nodejs.org/en/download)
- Git
- Microsoft Edge WebView2 Runtime
- for the MSI package, also install the [.NET SDK](https://dotnet.microsoft.com/download)
  and WiX Toolset v4

You can check the installed tool versions in PowerShell:

```powershell
go version
node --version
npm --version
dotnet --version
```

## Building the EXE Files

### Option A: PowerShell

Run the following commands from the repository root:

```powershell
New-Item -ItemType Directory -Force .\bin | Out-Null

go build -o .\bin\fleetctrl-client.exe .\cmd\main

Push-Location .\cmd\ui
go run github.com/wailsapp/wails/v2/cmd/wails@v2.13.0 build `
  -clean `
  -platform windows/amd64 `
  -webview2 download `
  -o fleetctrl-ui.exe
Pop-Location

Copy-Item .\cmd\ui\build\bin\fleetctrl-ui.exe `
  .\bin\fleetctrl-ui.exe -Force
```

When building the UI, Wails automatically runs `npm install` and
`npm run build` as configured in `cmd/ui/wails.json`.

The resulting files are:

```text
bin\fleetctrl-client.exe
bin\fleetctrl-ui.exe
```

### Option B: Make

If you use Git Bash, MSYS2, or another environment with GNU Make:

```bash
make build
```

To build only the desktop UI, run:

```bash
make build-ui
```

## Creating the MSI Installer

First, install WiX Toolset and the extensions used by the installer:

```powershell
dotnet tool install --global wix
wix extension add -g WixToolset.UI.wixext
wix extension add -g WixToolset.Util.wixext
wix --version
```

Then build both EXE files as described in the previous section and create the
MSI package. Replace the version value with the current three-part product
version:

```powershell
$Version = "2.0.2"

wix build .\installer\installer.wxs `
  -ext WixToolset.UI.wixext `
  -ext WixToolset.Util.wixext `
  -d Version=$Version `
  -arch x64 `
  -o .\bin\fleetctrl-client.msi
```

The resulting installer will be located at `bin\fleetctrl-client.msi`.

## Installation

### Recommended MSI Installation

Open PowerShell as an administrator and run:

```powershell
msiexec /i .\bin\fleetctrl-client.msi
```

The installer prompts for an enrollment token and the server URL. It then:

- installs the files in `C:\Program Files\fleetctrl`;
- creates and starts the `fleetctrl-client` service;
- configures the service to start automatically;
- creates a **FleetCtrl** shortcut in the Start menu;
- stores client data in `C:\ProgramData\fleetctrl`.

For an unattended installation without a dialog, run:

```powershell
msiexec /i .\bin\fleetctrl-client.msi `
  /qn `
  /l*v .\fleetctrl-install.log `
  ENROLL_TOKEN="<ENROLLMENT_TOKEN>" `
  SERVER_URL="https://fleetctrl.example.com"
```

The installation log will be saved as `fleetctrl-install.log` in the current
directory.

### Manual Service-Only Installation

This option installs only the Windows service. It does not copy the desktop UI
or create a Start menu shortcut. Use the MSI package for a complete
installation.

In PowerShell running as an administrator:

```powershell
.\bin\fleetctrl-client.exe install `
  --token "<ENROLLMENT_TOKEN>" `
  --url "https://fleetctrl.example.com"
```

The service copies its executable to `C:\Program Files\fleetctrl\client.exe`.

## Verifying the Installation

Check the service status:

```powershell
Get-Service fleetctrl-client
```

Check the installed files:

```powershell
Get-Item "C:\Program Files\fleetctrl\client.exe"
Get-Item "C:\Program Files\fleetctrl\fleetctrl-ui.exe"
```

Launch the desktop application from the Start menu or directly:

```powershell
& "C:\Program Files\fleetctrl\fleetctrl-ui.exe"
```

The UI displays service availability, the most recent synchronization, and the
status of applications assigned to the device. It communicates with the
service only locally through a secure named pipe.

## Updating

Build the MSI package with a higher version number and run it in the same way as
for the initial installation:

```powershell
msiexec /i .\bin\fleetctrl-client.msi
```

The installer automatically replaces the previous version.

## Uninstallation

### MSI Installation

Use **Installed apps** in Windows or run:

```powershell
msiexec /x .\bin\fleetctrl-client.msi
```

For an unattended uninstallation:

```powershell
msiexec /x .\bin\fleetctrl-client.msi /qn
```

By default, the device identity is preserved so that the client can reconnect
to the same record after a future installation. To remove all device data:

```powershell
msiexec /x .\bin\fleetctrl-client.msi /qn PRESERVE_DEVICE_DATA=0
```

### Manually Installed Service

In PowerShell running as an administrator:

```powershell
& "C:\Program Files\fleetctrl\client.exe" remove
```

To also remove the device identity:

```powershell
& "C:\Program Files\fleetctrl\client.exe" remove --delete-device-id
```

## Logs and Troubleshooting

Service log:

```text
C:\Program Files\fleetctrl\client.log
```

If the installation fails:

1. Make sure PowerShell is running as an administrator.
2. Make sure the server URL is accessible from the target computer.
3. Check that the enrollment token is valid.
4. For MSI installations, use the `/l*v` option as shown above.
5. If the UI does not start, make sure Microsoft Edge WebView2 Runtime is
   installed.
