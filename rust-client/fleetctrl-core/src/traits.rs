use anyhow::Result;
use std::{path::Path, time::Duration};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessOutput {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait RegistryStore: Send + Sync {
    fn get_string(&self, path: &str, name: &str) -> Result<Option<String>>;
    fn get_u32(&self, path: &str, name: &str) -> Result<Option<u32>>;
    fn set_string(&self, path: &str, name: &str, value: &str) -> Result<()>;
    fn set_u32(&self, path: &str, name: &str, value: u32) -> Result<()>;
    fn delete_value(&self, path: &str, name: &str) -> Result<()>;
    fn ensure_key(&self, path: &str) -> Result<()>;
}

pub trait SecretStore: Send + Sync {
    fn save_machine_secret(&self, path: &Path, bytes: &[u8]) -> Result<()>;
    fn load_machine_secret(&self, path: &Path) -> Result<Vec<u8>>;
}

pub trait SystemInfoProvider: Send + Sync {
    fn computer_name(&self) -> Result<String>;
    fn rustdesk_id(&self) -> Result<String>;
    fn computer_ip(&self) -> Result<String>;
    fn os_caption(&self) -> Result<String>;
    fn os_version(&self) -> Result<String>;
    fn current_user(&self) -> Result<String>;
    fn intune_id(&self) -> Result<String>;
}

pub trait ServiceControl: Send + Sync {
    fn install_service(&self, service_name: &str, display_name: &str, exe_path: &Path) -> Result<()>;
    fn remove_service(&self, service_name: &str) -> Result<()>;
    fn start_service(&self, service_name: &str) -> Result<()>;
    fn stop_service(&self, service_name: &str) -> Result<()>;
    fn service_exists(&self, service_name: &str) -> Result<bool>;
    fn is_running(&self, service_name: &str) -> Result<bool>;
}

pub trait ProcessRunner: Send + Sync {
    fn run(
        &self,
        exe: &str,
        args: &[&str],
        timeout: Duration,
        cwd: Option<&Path>,
    ) -> Result<ProcessOutput>;
}

pub trait UpdateInstaller: Send + Sync {
    fn is_msi_installation(&self) -> Result<bool>;
    fn apply_exe_update(&self, new_binary: &Path) -> Result<()>;
    fn apply_msi_update(&self, msi_path: &Path) -> Result<()>;
}
