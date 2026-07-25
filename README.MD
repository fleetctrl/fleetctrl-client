# FleetCtrl Client pro Windows

FleetCtrl Client se skládá ze dvou programů:

- `fleetctrl-client.exe` – Windows služba, která komunikuje se serverem FleetCtrl.
- `fleetctrl-ui.exe` – lokální desktopová aplikace pro monitoring služby.

Pro běžnou instalaci je doporučený MSI balíček. Nainstaluje oba programy,
zaregistruje službu a vytvoří zástupce **FleetCtrl** v nabídce Start.

## Požadavky pro sestavení

Sestavení provádějte na 64bitovém Windows 10 nebo Windows 11.

- [Go 1.25 nebo novější](https://go.dev/dl/)
- [Node.js 20 nebo novější](https://nodejs.org/en/download)
- Git
- Microsoft Edge WebView2 Runtime
- pro MSI také [.NET SDK](https://dotnet.microsoft.com/download) a WiX Toolset v4

Verze nástrojů lze zkontrolovat v PowerShellu:

```powershell
go version
node --version
npm --version
dotnet --version
```

## Sestavení EXE souborů

### Varianta A: PowerShell

V kořenové složce repozitáře spusťte:

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

Wails během sestavení UI automaticky spustí `npm install` a `npm run build`
podle souboru `cmd/ui/wails.json`.

Výsledkem jsou:

```text
bin\fleetctrl-client.exe
bin\fleetctrl-ui.exe
```

### Varianta B: Make

Pokud používáte Git Bash, MSYS2 nebo jiné prostředí s GNU Make:

```bash
make build
```

Pouze desktopové UI lze sestavit příkazem:

```bash
make build-ui
```

## Vytvoření MSI instalátoru

Nejdříve nainstalujte WiX Toolset a rozšíření používaná instalátorem:

```powershell
dotnet tool install --global wix
wix extension add -g WixToolset.UI.wixext
wix extension add -g WixToolset.Util.wixext
wix --version
```

Potom sestavte oba EXE soubory podle předchozí kapitoly a vytvořte MSI.
Hodnotu verze nahraďte aktuální tříčástkovou verzí produktu:

```powershell
$Version = "2.0.2"

wix build .\installer\installer.wxs `
  -ext WixToolset.UI.wixext `
  -ext WixToolset.Util.wixext `
  -d Version=$Version `
  -arch x64 `
  -o .\bin\fleetctrl-client.msi
```

Výsledný instalátor bude v `bin\fleetctrl-client.msi`.

## Instalace

### Doporučená instalace přes MSI

Otevřete PowerShell jako správce a spusťte:

```powershell
msiexec /i .\bin\fleetctrl-client.msi
```

Instalátor si vyžádá enrollment token a URL serveru. Potom:

- nainstaluje soubory do `C:\Program Files\fleetctrl`;
- vytvoří a spustí službu `fleetctrl-client`;
- nastaví automatické spouštění služby;
- vytvoří zástupce **FleetCtrl** v nabídce Start;
- uloží data klienta do `C:\ProgramData\fleetctrl`.

Pro tichou instalaci bez dialogu použijte:

```powershell
msiexec /i .\bin\fleetctrl-client.msi `
  /qn `
  /l*v .\fleetctrl-install.log `
  ENROLL_TOKEN="<ENROLLMENT_TOKEN>" `
  SERVER_URL="https://fleetctrl.example.com"
```

Instalační log bude uložen do `fleetctrl-install.log` v aktuální složce.

### Ruční instalace pouze služby

Tato varianta nainstaluje jen Windows službu. Nekopíruje desktopové UI a
nevytvoří zástupce v nabídce Start. Pro kompletní instalaci použijte MSI.

V PowerShellu spuštěném jako správce:

```powershell
.\bin\fleetctrl-client.exe install `
  --token "<ENROLLMENT_TOKEN>" `
  --url "https://fleetctrl.example.com"
```

Služba zkopíruje svůj spustitelný soubor do
`C:\Program Files\fleetctrl\client.exe`.

## Ověření instalace

Stav služby:

```powershell
Get-Service fleetctrl-client
```

Nainstalované soubory:

```powershell
Get-Item "C:\Program Files\fleetctrl\client.exe"
Get-Item "C:\Program Files\fleetctrl\fleetctrl-ui.exe"
```

Desktopovou aplikaci spusťte z nabídky Start nebo přímo:

```powershell
& "C:\Program Files\fleetctrl\fleetctrl-ui.exe"
```

UI zobrazuje dostupnost služby, poslední synchronizace a stav aplikací
přiřazených zařízení. Se službou komunikuje pouze lokálně přes zabezpečenou
named pipe.

## Aktualizace

Sestavte MSI s vyšší verzí a spusťte jej stejným způsobem jako při instalaci:

```powershell
msiexec /i .\bin\fleetctrl-client.msi
```

Instalátor předchozí verzi automaticky nahradí.

## Odinstalace

### Instalace provedená přes MSI

Použijte **Nainstalované aplikace** ve Windows nebo spusťte:

```powershell
msiexec /x .\bin\fleetctrl-client.msi
```

Tichá odinstalace:

```powershell
msiexec /x .\bin\fleetctrl-client.msi /qn
```

Ve výchozím stavu se zachová identita zařízení, aby se klient mohl při další
instalaci připojit ke stejnému záznamu. Pro odstranění všech dat zařízení:

```powershell
msiexec /x .\bin\fleetctrl-client.msi /qn PRESERVE_DEVICE_DATA=0
```

### Ručně nainstalovaná služba

V PowerShellu spuštěném jako správce:

```powershell
& "C:\Program Files\fleetctrl\client.exe" remove
```

Včetně identity zařízení:

```powershell
& "C:\Program Files\fleetctrl\client.exe" remove --delete-device-id
```

## Logy a řešení problémů

Log služby:

```text
C:\Program Files\fleetctrl\client.log
```

Pokud instalace selže:

1. Ověřte, že PowerShell běží jako správce.
2. Ověřte dostupnost URL serveru z cílového počítače.
3. Zkontrolujte platnost enrollment tokenu.
4. U MSI instalace použijte přepínač `/l*v`, jak je uvedeno výše.
5. Pokud se nespustí UI, ověřte instalaci Microsoft Edge WebView2 Runtime.
