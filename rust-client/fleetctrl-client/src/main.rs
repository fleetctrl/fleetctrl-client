use anyhow::Result;
use clap::{Parser, Subcommand};
use fleetctrl_core::constants;

#[cfg(windows)]
use anyhow::{anyhow, Context};
#[cfg(windows)]
use fleetctrl_core::{
    auth::{AuthService, AuthenticatedHttpClient},
    config::{normalize_server_url, InstallConfig},
    install::Installer,
    service::CoreService,
    traits::{ProcessRunner, RegistryStore, SecretStore, SystemInfoProvider, UpdateInstaller},
    update::Updater,
};
#[cfg(windows)]
use fleetctrl_win::{
    CommandProcessRunner, DpapiSecretStore, WindowsRegistry, WindowsServiceControl, WindowsSystemInfo,
};
#[cfg(windows)]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
#[cfg(windows)]
use tokio::runtime::Runtime;
#[cfg(windows)]
use tokio_util::sync::CancellationToken;
#[cfg(windows)]
use tracing::error;
#[cfg(windows)]
use tracing_subscriber::fmt::MakeWriter;

#[derive(Parser, Debug)]
#[command(name = "fleetctrl-client", version = constants::VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Install {
        #[arg(long = "token")]
        token: String,
        #[arg(long = "url")]
        url: String,
        #[arg(long = "msi", default_value_t = false)]
        msi: bool,
        #[arg(long = "installer-log")]
        installer_log: Option<String>,
    },
    Remove {
        #[arg(long = "delete-device-id", default_value_t = false)]
        delete_device_id: bool,
        #[arg(long = "installer-log")]
        installer_log: Option<String>,
    },
    Update {
        #[arg(long = "installer-log")]
        installer_log: Option<String>,
    },
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct LogFileFactory {
    path: PathBuf,
}

#[cfg(windows)]
struct RotatingLogWriter {
    path: PathBuf,
}

#[cfg(windows)]
impl<'a> MakeWriter<'a> for LogFileFactory {
    type Writer = RotatingLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingLogWriter {
            path: self.path.clone(),
        }
    }
}

#[cfg(windows)]
impl Write for RotatingLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(metadata) = fs::metadata(&self.path) {
            if metadata.len() > constants::MAX_LOG_SIZE_BYTES {
                let old_path = self.path.with_extension("log.old");
                let _ = fs::remove_file(&old_path);
                let _ = fs::rename(&self.path, &old_path);
            }
        }

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
struct WindowsUpdaterControl {
    runner: Arc<dyn ProcessRunner>,
    registry: Arc<dyn RegistryStore>,
}

#[cfg(windows)]
impl UpdateInstaller for WindowsUpdaterControl {
    fn is_msi_installation(&self) -> Result<bool> {
        Ok(self
            .registry
            .get_u32(constants::REGISTRY_ROOT_KEY, constants::INSTALLED_VIA_MSI_VALUE_NAME)?
            .unwrap_or_default()
            > 0)
    }

    fn apply_exe_update(&self, new_binary: &Path) -> Result<()> {
        self.runner.run(
            new_binary
                .to_str()
                .ok_or_else(|| anyhow!("invalid update path"))?,
            &["update"],
            std::time::Duration::from_secs(30),
            None,
        )?;
        Ok(())
    }

    fn apply_msi_update(&self, msi_path: &Path) -> Result<()> {
        self.runner.run(
            "msiexec",
            &[
                "/i",
                msi_path
                    .to_str()
                    .ok_or_else(|| anyhow!("invalid MSI path"))?,
                "/qn",
                "/norestart",
            ],
            std::time::Duration::from_secs(60),
            None,
        )?;
        Ok(())
    }
}

#[cfg(windows)]
fn build_http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(constants::REQUEST_TIMEOUT)
        .build()?)
}

#[cfg(windows)]
fn init_logging(path: PathBuf) -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(LogFileFactory { path })
        .with_ansi(false)
        .try_init()
        .map_err(|err| anyhow!("failed to initialize logging: {err}"))
}

#[cfg(windows)]
fn installer_log_path(explicit: Option<String>) -> PathBuf {
    explicit
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(constants::INSTALLER_LOG_FILENAME))
}

#[cfg(windows)]
fn build_runtime_components(server_url: String) -> Result<RuntimeComponents> {
    let registry: Arc<dyn RegistryStore> = Arc::new(WindowsRegistry::default());
    let secret_store: Arc<dyn SecretStore> = Arc::new(DpapiSecretStore::default());
    let process_runner: Arc<dyn ProcessRunner> = Arc::new(CommandProcessRunner);
    let system_info: Arc<dyn SystemInfoProvider> = Arc::new(WindowsSystemInfo);
    let service_control = Arc::new(WindowsServiceControl::new());
    let base_client = build_http_client()?;
    let auth_service = Arc::new(AuthService::new(
        server_url.clone(),
        base_client.clone(),
        Arc::clone(&secret_store),
        Arc::clone(&registry),
    ));
    let updater: Arc<dyn UpdateInstaller> = Arc::new(WindowsUpdaterControl {
        runner: Arc::clone(&process_runner),
        registry: Arc::clone(&registry),
    });
    let updater = Arc::new(Updater::new(server_url, base_client.clone(), updater));
    let http = Arc::new(AuthenticatedHttpClient::new(
        base_client,
        Arc::clone(&auth_service),
        Arc::clone(&registry),
        Some(updater),
    ));

    Ok(RuntimeComponents {
        registry,
        process_runner,
        system_info,
        service_control,
        auth_service,
        http,
    })
}

#[cfg(windows)]
struct RuntimeComponents {
    registry: Arc<dyn RegistryStore>,
    process_runner: Arc<dyn ProcessRunner>,
    system_info: Arc<dyn SystemInfoProvider>,
    service_control: Arc<WindowsServiceControl>,
    auth_service: Arc<AuthService>,
    http: Arc<AuthenticatedHttpClient>,
}

#[cfg(windows)]
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Install {
            token,
            url,
            msi,
            installer_log,
        }) => {
            let log_path = installer_log_path(installer_log);
            init_logging(log_path.clone())?;
            let server_url = normalize_server_url(&url)?;
            let runtime = Runtime::new()?;
            runtime.block_on(async move {
                let components = build_runtime_components(server_url.clone())?;
                let installer = Installer::new(
                    Arc::clone(&components.registry),
                    components.service_control.clone(),
                    Arc::clone(&components.process_runner),
                    Arc::clone(&components.system_info),
                    Arc::clone(&components.auth_service),
                );
                let current_exe = std::env::current_exe()?;
                installer
                    .install(
                        &current_exe,
                        &InstallConfig {
                            enroll_token: token,
                            server_url,
                            is_msi: msi,
                            installer_log_path: Some(log_path.to_string_lossy().to_string()),
                        },
                    )
                    .await
            })?;
            Ok(())
        }
        Some(Commands::Remove {
            delete_device_id,
            installer_log,
        }) => {
            let log_path = installer_log_path(installer_log);
            init_logging(log_path)?;
            let registry: Arc<dyn RegistryStore> = Arc::new(WindowsRegistry::default());
            let secret_store: Arc<dyn SecretStore> = Arc::new(DpapiSecretStore::default());
            let process_runner: Arc<dyn ProcessRunner> = Arc::new(CommandProcessRunner);
            let system_info: Arc<dyn SystemInfoProvider> = Arc::new(WindowsSystemInfo);
            let service_control = Arc::new(WindowsServiceControl::new());
            let base_client = build_http_client()?;
            let server_url = registry
                .get_string(constants::REGISTRY_ROOT_KEY, constants::SERVER_URL_VALUE_NAME)?
                .unwrap_or_default();
            let auth_service = Arc::new(AuthService::new(
                server_url,
                base_client,
                secret_store,
                Arc::clone(&registry),
            ));
            let installer = Installer::new(
                Arc::clone(&registry),
                service_control,
                process_runner,
                system_info,
                auth_service,
            );
            Runtime::new()?.block_on(async move { installer.remove(!delete_device_id).await })?;
            Ok(())
        }
        Some(Commands::Update { installer_log }) => {
            let log_path = installer_log_path(installer_log);
            init_logging(log_path)?;
            let registry: Arc<dyn RegistryStore> = Arc::new(WindowsRegistry::default());
            let secret_store: Arc<dyn SecretStore> = Arc::new(DpapiSecretStore::default());
            let process_runner: Arc<dyn ProcessRunner> = Arc::new(CommandProcessRunner);
            let system_info: Arc<dyn SystemInfoProvider> = Arc::new(WindowsSystemInfo);
            let service_control = Arc::new(WindowsServiceControl::new());
            let base_client = build_http_client()?;
            let server_url = registry
                .get_string(constants::REGISTRY_ROOT_KEY, constants::SERVER_URL_VALUE_NAME)?
                .unwrap_or_default();
            let auth_service = Arc::new(AuthService::new(
                server_url,
                base_client,
                secret_store,
                Arc::clone(&registry),
            ));
            let installer = Installer::new(
                Arc::clone(&registry),
                service_control,
                process_runner,
                system_info,
                auth_service,
            );
            let current_exe = std::env::current_exe()?;
            Runtime::new()?.block_on(async move { installer.update(&current_exe).await })?;
            Ok(())
        }
        None => {
            init_logging(PathBuf::from(format!(r"{}\client.log", constants::TARGET_DIR)))?;
            run_windows_service()
        }
    }
}

#[cfg(not(windows))]
fn main() -> Result<()> {
    Err(anyhow::anyhow!("fleetctrl-client is only supported on Windows"))
}

#[cfg(windows)]
fn run_windows_service() -> Result<()> {
    use std::{ffi::OsString, sync::mpsc};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service_inner() {
            error!("service exited with error: {err:#}");
        }
    }

    fn run_service_inner() -> Result<()> {
        let (tx, rx) = mpsc::channel();
        let status_handle = service_control_handler::register(
            constants::SERVICE_NAME,
            move |control_event| match control_event {
                windows_service::service::ServiceControl::Stop
                | windows_service::service::ServiceControl::Shutdown => {
                    let _ = tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                windows_service::service::ServiceControl::Interrogate => {
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        let registry = WindowsRegistry::default();
        let server_url = registry
            .get_string(constants::REGISTRY_ROOT_KEY, constants::SERVER_URL_VALUE_NAME)?
            .ok_or_else(|| anyhow!("missing server_url registry value"))?;
        let runtime = Runtime::new()?;
        runtime.block_on(async move {
            let components = build_runtime_components(server_url)?;
            let service = CoreService::new(
                Arc::clone(&components.auth_service),
                Arc::clone(&components.http),
                Arc::clone(&components.system_info),
                Arc::clone(&components.process_runner),
            );
            let shutdown = CancellationToken::new();
            let canceller = shutdown.clone();
            std::thread::spawn(move || {
                let _ = rx.recv();
                canceller.cancel();
            });
            service.run(shutdown).await
        })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }

    service_dispatcher::start(constants::SERVICE_NAME, ffi_service_main)
        .context("failed to start service dispatcher")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn parses_install_command() {
        let cli = Cli::parse_from([
            "fleetctrl-client",
            "install",
            "--token",
            "abc",
            "--url",
            "https://fleet.example.com",
            "--msi",
        ]);
        match cli.command.unwrap() {
            Commands::Install { token, url, msi, .. } => {
                assert_eq!(token, "abc");
                assert_eq!(url, "https://fleet.example.com");
                assert!(msi);
            }
            _ => panic!("expected install command"),
        }
    }

    #[test]
    fn parses_remove_command() {
        let cli = Cli::parse_from([
            "fleetctrl-client",
            "remove",
            "--delete-device-id",
        ]);
        match cli.command.unwrap() {
            Commands::Remove { delete_device_id, .. } => assert!(delete_device_id),
            _ => panic!("expected remove command"),
        }
    }
}
