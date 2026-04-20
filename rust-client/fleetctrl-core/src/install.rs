use crate::{
    auth::AuthService,
    config::{normalize_server_url, InstallConfig},
    constants,
    models::Tokens,
    traits::{ProcessRunner, RegistryStore, ServiceControl, SystemInfoProvider},
};
use anyhow::{anyhow, Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tracing::{info, warn};

pub struct Installer {
    registry: Arc<dyn RegistryStore>,
    service_control: Arc<dyn ServiceControl>,
    process_runner: Arc<dyn ProcessRunner>,
    system_info: Arc<dyn SystemInfoProvider>,
    auth_service: Arc<AuthService>,
}

impl Installer {
    pub fn new(
        registry: Arc<dyn RegistryStore>,
        service_control: Arc<dyn ServiceControl>,
        process_runner: Arc<dyn ProcessRunner>,
        system_info: Arc<dyn SystemInfoProvider>,
        auth_service: Arc<AuthService>,
    ) -> Self {
        Self {
            registry,
            service_control,
            process_runner,
            system_info,
            auth_service,
        }
    }

    pub async fn install(&self, current_exe: &Path, config: &InstallConfig) -> Result<()> {
        let server_url = normalize_server_url(&config.server_url)?;
        for attempt in 1..=3 {
            if self.auth_service.healthcheck_once().await? {
                break;
            }
            if attempt == 3 {
                return Err(anyhow!("failed to reach server after 3 attempts"));
            }
            tokio::time::sleep(Duration::from_secs(attempt)).await;
        }

        if self.service_control.service_exists(constants::SERVICE_NAME)? {
            self.remove(true).await?;
        }

        fs::create_dir_all(constants::TARGET_DIR)?;
        fs::create_dir_all(constants::PROGRAM_DATA_DIR)?;
        self.registry.ensure_key(constants::COMPANY_REGISTRY_KEY)?;
        self.registry.ensure_key(constants::REGISTRY_ROOT_KEY)?;
        self.registry.set_string(
            constants::REGISTRY_ROOT_KEY,
            constants::VERSION_VALUE_NAME,
            constants::VERSION,
        )?;
        self.registry.set_string(
            constants::REGISTRY_ROOT_KEY,
            constants::SERVER_URL_VALUE_NAME,
            &server_url,
        )?;
        if config.is_msi {
            self.registry.set_u32(
                constants::REGISTRY_ROOT_KEY,
                constants::INSTALLED_VIA_MSI_VALUE_NAME,
                1,
            )?;
        }

        let tokens = self.ensure_enrollment(&config.enroll_token).await?;
        self.auth_service.save_refresh_token(&tokens.refresh_token)?;

        copy_executable(current_exe)?;
        self.service_control.install_service(
            constants::SERVICE_NAME,
            constants::SERVICE_DISPLAY_NAME,
            Path::new(&constants::target_exe_path()),
        )?;
        self.service_control.start_service(constants::SERVICE_NAME)?;
        Ok(())
    }

    pub async fn remove(&self, preserve_device_id: bool) -> Result<()> {
        let _ = self.registry.set_string(
            constants::REGISTRY_ROOT_KEY,
            constants::VERSION_VALUE_NAME,
            "0",
        );
        if !preserve_device_id {
            let _ = self
                .registry
                .delete_value(constants::REGISTRY_ROOT_KEY, constants::DEVICE_ID_VALUE_NAME);
        }

        if self.service_control.service_exists(constants::SERVICE_NAME)? {
            if self.service_control.is_running(constants::SERVICE_NAME)? {
                let _ = self.service_control.stop_service(constants::SERVICE_NAME);
            }
            self.service_control.remove_service(constants::SERVICE_NAME)?;
        }

        cleanup_program_data(self.process_runner.as_ref(), preserve_device_id)?;
        take_ownership_and_delete(self.process_runner.as_ref(), Path::new(constants::TARGET_DIR))?;
        Ok(())
    }

    pub async fn update(&self, current_exe: &Path) -> Result<()> {
        if self.service_control.service_exists(constants::SERVICE_NAME)? {
            if self.service_control.is_running(constants::SERVICE_NAME)? {
                self.service_control.stop_service(constants::SERVICE_NAME)?;
            }
        }

        copy_executable(current_exe)?;
        let _ = self.registry.set_string(
            constants::REGISTRY_ROOT_KEY,
            constants::VERSION_VALUE_NAME,
            constants::VERSION,
        );
        self.service_control.start_service(constants::SERVICE_NAME)?;
        Ok(())
    }

    async fn ensure_enrollment(&self, enroll_token: &str) -> Result<Tokens> {
        let existing_device_id = self.auth_service.load_device_id()?;
        if let Some(device_id) = existing_device_id {
            if self.auth_service.private_jwk_exists() {
                match self.auth_service.is_enrolled(&device_id).await {
                    Ok(true) => match self.auth_service.recover_tokens().await {
                        Ok(tokens) => return Ok(tokens),
                        Err(err) => warn!("recover with existing device failed: {err:#}"),
                    },
                    Ok(false) => info!("existing device is no longer enrolled, performing fresh enroll"),
                    Err(err) => warn!("failed to validate existing enrollment: {err:#}"),
                }
            }
        }

        let enrollment = self
            .auth_service
            .enroll(enroll_token, &self.system_info.computer_name()?)
            .await?;
        self.auth_service.save_device_id(&enrollment.device_id)?;
        Ok(enrollment.tokens)
    }
}

pub fn copy_executable(source_path: &Path) -> Result<()> {
    let target_path = PathBuf::from(constants::target_exe_path());
    if source_path.canonicalize().ok() == target_path.canonicalize().ok() {
        info!("binary is already in target location, skipping copy");
        return Ok(());
    }

    if Path::new(constants::TARGET_DIR).exists() {
        fs::remove_dir_all(constants::TARGET_DIR)
            .with_context(|| format!("failed to remove {}", constants::TARGET_DIR))?;
    }
    fs::create_dir_all(constants::TARGET_DIR)?;
    fs::copy(source_path, &target_path)?;
    Ok(())
}

fn cleanup_program_data(process_runner: &dyn ProcessRunner, preserve_device_id: bool) -> Result<()> {
    let program_data = Path::new(constants::PROGRAM_DATA_DIR);
    if !program_data.exists() {
        return Ok(());
    }
    if !preserve_device_id {
        return take_ownership_and_delete(process_runner, program_data);
    }

    for entry in fs::read_dir(program_data)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().eq_ignore_ascii_case("certs") {
            continue;
        }
        take_ownership_and_delete(process_runner, &entry.path())?;
    }
    Ok(())
}

fn take_ownership_and_delete(process_runner: &dyn ProcessRunner, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let path_str = path.to_string_lossy().to_string();
    process_runner.run("takeown", &["/F", &path_str, "/R", "/D", "Y"], Duration::from_secs(120), None)?;
    process_runner.run(
        "icacls",
        &[&path_str, "/grant", "Administrators:F", "/T"],
        Duration::from_secs(120),
        None,
    )?;
    if path.is_dir() {
        process_runner.run("cmd", &["/C", "rd", "/S", "/Q", &path_str], Duration::from_secs(120), None)?;
    } else {
        process_runner.run("cmd", &["/C", "del", "/F", "/Q", &path_str], Duration::from_secs(120), None)?;
    }
    Ok(())
}
