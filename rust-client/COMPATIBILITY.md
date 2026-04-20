# FleetCtrl Rust Client Compatibility Freeze

This document records the externally visible behavior that the Rust client must preserve while it replaces the Go implementation for the core agent milestone.

## CLI Contract

The Rust binary preserves the same command surface:

- `client.exe install --token "<ENROLLMENT_TOKEN>" --url "https://server.example.com" [--msi --installer-log "<PATH>"]`
- `client.exe remove [--delete-device-id] [--installer-log "<PATH>"]`
- `client.exe update [--installer-log "<PATH>"]`
- no explicit subcommand means the process starts as a Windows service host

## Windows Contract

- Service name: `fleetctrl-client`
- Service display name: `fleetctrl client`
- Install directory: `C:\Program Files\fleetctrl`
- Program data directory: `C:\ProgramData\fleetctrl`
- Registry root: `HKLM\SOFTWARE\fleetctrl\client`
- Device identity:
  - `DeviceID` remains in `HKLM\SOFTWARE\fleetctrl\client\DeviceID`
  - private JWK remains in `C:\ProgramData\fleetctrl\certs\priv.jwk`
  - refresh token remains in `C:\ProgramData\fleetctrl\tokens\refresh_token.txt`

## Registry Keys

- `version`: string
- `server_url`: string
- `installed_via_msi`: DWORD
- `DeviceID`: string

## Server Endpoints

- `GET /health`
- `POST /enroll`
- `GET /devices/{deviceId}/is-enrolled`
- `POST /token/refresh`
- `POST /token/recover`
- `PATCH /computer/rustdesk-sync`
- `GET /tasks`
- `PATCH /task/{id}`
- update metadata comes from `X-Client-Update`

## Polling And Retry Behavior

- health and enrollment bootstrap uses exponential backoff starting at 5 seconds and capped at 15 minutes
- RustDesk sync loop runs every 5 minutes
- task polling loop runs every 5 minutes
- service health wait loop uses 60 second retries

## Milestone 1 Functional Difference

- `apps/assigned` polling is intentionally disabled
- `client.db` is not created
- winget/win32 app management remains in the Go client until a later migration wave
