<#
.SYNOPSIS
Signs EXE and MSI files with the FleetCtrl code-signing certificate.

.DESCRIPTION
Loads the certificate from a PFX file and adds an Authenticode SHA-256 signature
with a timestamp to every given file. The timestamp keeps signatures valid after
the certificate expires.

The PFX password is taken from -PfxPassword, then from the CODESIGN_PFX_PASSWORD
environment variable, and is prompted for otherwise.

.EXAMPLE
.\scripts\sign.ps1 .\bin\fleetctrl-client.exe .\bin\fleetctrl-ui.exe

.EXAMPLE
.\scripts\sign.ps1 .\bin\*.msi -PfxPath D:\keys\fleetctrl-codesign.pfx
#>
[CmdletBinding()]
param(
    # Files to sign. Wildcards are allowed.
    [Parameter(Mandatory, Position = 0, ValueFromRemainingArguments)]
    [string[]]$Path,

    [string]$PfxPath = (Join-Path $PSScriptRoot "..\certs\fleetctrl-codesign.pfx"),

    [SecureString]$PfxPassword,

    # Empty string disables timestamping (not recommended).
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $PfxPath)) {
    throw "PFX file not found: $PfxPath. Create it with .\scripts\new-codesign-cert.ps1 or pass -PfxPath."
}

if (-not $PfxPassword) {
    if ($env:CODESIGN_PFX_PASSWORD) {
        $PfxPassword = ConvertTo-SecureString $env:CODESIGN_PFX_PASSWORD -AsPlainText -Force
    } else {
        $PfxPassword = Read-Host "PFX password" -AsSecureString
    }
}

$files = foreach ($item in $Path) { (Resolve-Path $item).Path }

$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path $PfxPath).Path, $PfxPassword)
try {
    if (-not $cert.HasPrivateKey) {
        throw "$PfxPath does not contain a private key."
    }
    if ($cert.NotAfter -lt (Get-Date)) {
        throw "Certificate $($cert.Thumbprint) expired on $($cert.NotAfter.ToString('yyyy-MM-dd'))."
    }

    foreach ($file in $files) {
        $params = @{
            FilePath      = $file
            Certificate   = $cert
            HashAlgorithm = "SHA256"
            IncludeChain  = "All"
        }
        if ($TimestampServer) {
            $params.TimestampServer = $TimestampServer
        }

        # Public timestamp servers occasionally fail, so retry a few times.
        $attempt = 0
        while ($true) {
            $attempt++
            try {
                Set-AuthenticodeSignature @params | Out-Null
                $signature = Get-AuthenticodeSignature -FilePath $file
                if ($signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
                    throw "signature missing after signing: $($signature.StatusMessage)"
                }
                if ($TimestampServer -and -not $signature.TimeStamperCertificate) {
                    throw "timestamp missing (server $TimestampServer)"
                }
                break
            } catch {
                if ($attempt -ge 3) {
                    throw "Failed to sign ${file}: $_"
                }
                Write-Warning "Signing $file failed (attempt $attempt): $_. Retrying..."
                Start-Sleep -Seconds (5 * $attempt)
            }
        }

        # On the build machine the status is usually UnknownError (self-signed root not
        # trusted); on computers that received the certificate via GPO it is Valid.
        Write-Host "Signed $file ($($signature.Status))"
    }
} finally {
    $cert.Dispose()
}
