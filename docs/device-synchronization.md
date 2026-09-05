# Device synchronization

Requires the Hub version providing `POST /computer/heartbeat` and `PATCH /computer/hardware-sync`. Deploy the Hub first; an older Hub returns errors for these new routes.

- Presence: immediately on service/console startup, then every minute. Runs independently of the synchronization coordinator, hardware queries, and application installations. Each HTTP attempt has a 30-second context deadline; failures are logged and retried on the next tick.
- Inventory: on startup, then every hour through the existing coordinator. Manual device/full synchronization still works. Failed hardware collection leaves the previous server inventory untouched and records a failed sync.
- Applications: existing 15-minute reconciliation schedule remains in place.

Windows CIM supplies CPU names, total physical cores and logical processors across all CPUs, installed RAM, and the Windows system volume's name, capacity and free bytes. The volume is read from `Win32_OperatingSystem.SystemDrive`, so it is not assumed to be C:. Collection is bounded to 45 seconds and uses the installed PowerShell without extra runtime dependencies.

The Hub uses server time for presence and inventory timestamps. Offline status is shown after five minutes without a check-in.

Validation:

```powershell
go test ./internal/... ./cmd/main/...
# Optional smoke test against the current Windows machine:
$env:FLEETCTRL_TEST_HARDWARE = '1'
go test ./internal/utils -run Hardware -v
```
