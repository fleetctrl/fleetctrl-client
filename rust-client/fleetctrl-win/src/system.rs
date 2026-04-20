use anyhow::{Context, Result};
use fleetctrl_core::traits::SystemInfoProvider;
use std::{env, process::Command};

#[cfg(windows)]
use winreg::{enums::*, RegKey};

#[derive(Debug, Default)]
pub struct WindowsSystemInfo;

impl SystemInfoProvider for WindowsSystemInfo {
    fn computer_name(&self) -> Result<String> {
        Ok(env::var("COMPUTERNAME").unwrap_or_default())
    }

    fn rustdesk_id(&self) -> Result<String> {
        let program_files = env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
        run_and_trim(
            Command::new(format!(r"{}\RustDesk\rustdesk.exe", program_files)).arg("--get-id"),
        )
    }

    fn computer_ip(&self) -> Result<String> {
        run_powershell("(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like '192.168.*' -or $_.IPAddress -like '10.*' -or $_.IPAddress -match '^172\\.(1[6-9]|2[0-9]|3[01])\\.' }).IPAddress | Select-Object -First 1")
    }

    fn os_caption(&self) -> Result<String> {
        run_powershell("(Get-CimInstance Win32_OperatingSystem).Caption")
    }

    fn os_version(&self) -> Result<String> {
        run_powershell("(Get-WmiObject Win32_OperatingSystem).Version")
    }

    fn current_user(&self) -> Result<String> {
        run_powershell("(Get-CimInstance -ClassName Win32_ComputerSystem).Username")
            .or_else(|_| run_powershell("$quserOutput = quser 2>$null; if ($quserOutput) { $lines = $quserOutput | Select-Object -Skip 1; foreach ($line in $lines) { if ($line -match 'Active') { $parts = $line.Trim() -split '\\s+'; if ($parts.Count -gt 0) { Write-Output $parts[0]; break }}}}"))
            .or_else(|_| run_powershell("$explorer = Get-WmiObject Win32_Process -Filter \"Name='explorer.exe'\" | Select-Object -First 1; if ($explorer) { $owner = $explorer.GetOwner(); if ($owner.Domain) { Write-Output \"$($owner.Domain)\\$($owner.User)\" } else { Write-Output $owner.User }}"))
    }

    fn intune_id(&self) -> Result<String> {
        #[cfg(windows)]
        {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            if let Ok(enrollments) = hklm.open_subkey_with_flags(r"SOFTWARE\Microsoft\Enrollments", KEY_ENUMERATE_SUB_KEYS) {
                for subkey_name in enrollments.enum_keys().flatten() {
                    if let Ok(subkey) = hklm.open_subkey_with_flags(
                        format!(r"SOFTWARE\Microsoft\Enrollments\{}", subkey_name),
                        KEY_QUERY_VALUE,
                    ) {
                        let upn: String = subkey.get_value("UPN").unwrap_or_default();
                        if upn.is_empty() {
                            continue;
                        }
                        let tenant_id: String = subkey.get_value("AADTenantID").unwrap_or_default();
                        if !tenant_id.is_empty() {
                            return Ok(tenant_id);
                        }
                    }
                }
            }
        }
        Ok(String::new())
    }
}

fn run_powershell(script: &str) -> Result<String> {
    run_and_trim(
        Command::new("powershell")
            .arg("-NoProfile")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(script),
    )
}

fn run_and_trim(command: &mut Command) -> Result<String> {
    let output = command.output().context("failed to run command")?;
    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
