<#
.SYNOPSIS
Creates a self-signed Authenticode code-signing certificate for FleetCtrl.

.DESCRIPTION
Generates an RSA 4096 / SHA-256 code-signing certificate (10 years by default)
and writes two files:

  <Name>.pfx  certificate WITH the private key, password protected.
              Keep it secret: anyone who has it can sign files your
              computers will trust.
  <Name>.cer  public certificate only. Distribute this one via GPO.

The certificate is removed from the current user's certificate store afterwards,
so the PFX file is the only copy of the private key. Back it up.

.EXAMPLE
.\scripts\new-codesign-cert.ps1

.EXAMPLE
.\scripts\new-codesign-cert.ps1 -Subject "CN=Contoso FleetCtrl Code Signing, O=Contoso" -ValidYears 10
#>
[CmdletBinding()]
param(
    # Distinguished name shown as the publisher of signed files.
    [string]$Subject = "CN=FleetCtrl Code Signing",

    [ValidateRange(1, 50)]
    [int]$ValidYears = 10,

    [string]$OutputDir = (Join-Path $PSScriptRoot "..\certs"),

    # Base file name of the generated .pfx and .cer files.
    [string]$Name = "fleetctrl-codesign",

    # PFX password. Prompted for when omitted.
    [SecureString]$Password
)

$ErrorActionPreference = "Stop"

function ConvertTo-PlainText([SecureString]$Value) {
    [System.Net.NetworkCredential]::new("", $Value).Password
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path
$pfxPath = Join-Path $OutputDir "$Name.pfx"
$cerPath = Join-Path $OutputDir "$Name.cer"

foreach ($path in $pfxPath, $cerPath) {
    if (Test-Path $path) {
        throw "$path already exists. Overwriting it would lose the existing key; delete it or choose another -Name."
    }
}

if (-not $Password) {
    $Password = Read-Host "PFX password" -AsSecureString
    $confirmation = Read-Host "Confirm PFX password" -AsSecureString
    if ((ConvertTo-PlainText $Password) -cne (ConvertTo-PlainText $confirmation)) {
        throw "Passwords do not match."
    }
}
if ((ConvertTo-PlainText $Password).Length -lt 12) {
    throw "Use a PFX password with at least 12 characters."
}

# The legacy CryptoAPI provider keeps the key usable by both Set-AuthenticodeSignature
# and signtool. CA=false stops the certificate from issuing other certificates once it
# sits in Trusted Root, and the code-signing EKU limits it to signing code.
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -FriendlyName "FleetCtrl Code Signing" `
    -KeyAlgorithm RSA `
    -KeyLength 4096 `
    -KeySpec Signature `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    -TextExtension @("2.5.29.19={critical}{text}ca=0") `
    -NotAfter (Get-Date).AddYears($ValidYears) `
    -CertStoreLocation "Cert:\CurrentUser\My"

try {
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $Password -CryptoAlgorithmOption AES256_SHA256 | Out-Null
    Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
} finally {
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
}

Write-Host ""
Write-Host "Code-signing certificate created" -ForegroundColor Green
Write-Host "  Subject:    $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Valid:      $($cert.NotBefore.ToString('yyyy-MM-dd')) - $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Private:    $pfxPath  (keep secret, back it up)"
Write-Host "  Public:     $cerPath  (import via GPO)"
Write-Host ""
Write-Host "Sign files:  .\scripts\sign.ps1 .\bin\fleetctrl-client.exe .\bin\fleetctrl-ui.exe"
