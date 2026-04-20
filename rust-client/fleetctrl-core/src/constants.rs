use std::time::Duration;

pub const VERSION: &str = "2.0.0";
pub const SERVICE_NAME: &str = "fleetctrl-client";
pub const SERVICE_DISPLAY_NAME: &str = "fleetctrl client";
pub const TARGET_DIR: &str = r"C:\Program Files\fleetctrl";
pub const TARGET_EXE_NAME: &str = "client.exe";
pub const PROGRAM_DATA_DIR: &str = r"C:\ProgramData\fleetctrl";
pub const COMPANY_REGISTRY_KEY: &str = r"SOFTWARE\fleetctrl";
pub const REGISTRY_ROOT_KEY: &str = r"SOFTWARE\fleetctrl\client";
pub const DEVICE_ID_VALUE_NAME: &str = "DeviceID";
pub const SERVER_URL_VALUE_NAME: &str = "server_url";
pub const VERSION_VALUE_NAME: &str = "version";
pub const INSTALLED_VIA_MSI_VALUE_NAME: &str = "installed_via_msi";
pub const MAX_LOG_SIZE_BYTES: u64 = 20 * 1024 * 1024;
pub const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(60);
pub const TASK_LOOP_INTERVAL: Duration = Duration::from_secs(300);
pub const RUSTDESK_SYNC_INTERVAL: Duration = Duration::from_secs(300);
pub const RETRY_INITIAL_DELAY: Duration = Duration::from_secs(5);
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(900);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);
pub const INSTALLER_LOG_FILENAME: &str = "FleetCtrlInstaller.log";

pub fn target_exe_path() -> String {
    format!(r"{}\{}", TARGET_DIR, TARGET_EXE_NAME)
}

pub fn refresh_token_path() -> String {
    format!(r"{}\tokens\refresh_token.txt", PROGRAM_DATA_DIR)
}

pub fn private_jwk_path() -> String {
    format!(r"{}\certs\priv.jwk", PROGRAM_DATA_DIR)
}
