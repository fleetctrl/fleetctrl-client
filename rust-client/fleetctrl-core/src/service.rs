use crate::{
    auth::{AuthService, AuthenticatedHttpClient},
    constants,
    models::{ComputerPayload, SetNetworkStringTask, SetPasswordTask, TaskEnvelope, TaskListResponse, Tokens},
    traits::{ProcessRunner, SystemInfoProvider},
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{task::JoinSet, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub struct CoreService {
    auth_service: Arc<AuthService>,
    http: Arc<AuthenticatedHttpClient>,
    system_info: Arc<dyn SystemInfoProvider>,
    process_runner: Arc<dyn ProcessRunner>,
}

impl CoreService {
    pub fn new(
        auth_service: Arc<AuthService>,
        http: Arc<AuthenticatedHttpClient>,
        system_info: Arc<dyn SystemInfoProvider>,
        process_runner: Arc<dyn ProcessRunner>,
    ) -> Self {
        Self {
            auth_service,
            http,
            system_info,
            process_runner,
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<()> {
        let device_id = self
            .auth_service
            .load_device_id()?
            .ok_or_else(|| anyhow!("DeviceID is missing. Re-enroll or reinstall the client."))?;

        self.wait_until_registered(&device_id, shutdown.clone()).await?;
        let tokens = self.bootstrap_tokens().await?;
        self.http.set_tokens(tokens).await;

        let mut tasks = JoinSet::new();
        tasks.spawn(sync_loop(
            Arc::clone(&self.http),
            Arc::clone(&self.system_info),
            self.auth_service.server_url().to_string(),
            shutdown.clone(),
        ));
        tasks.spawn(task_loop(
            Arc::clone(&self.http),
            Arc::clone(&self.process_runner),
            self.auth_service.server_url().to_string(),
            shutdown.clone(),
        ));

        shutdown.cancelled().await;
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    async fn wait_until_registered(&self, device_id: &str, shutdown: CancellationToken) -> Result<()> {
        let mut delay = constants::RETRY_INITIAL_DELAY;
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }

            if self.auth_service.healthcheck_once().await? {
                match self.auth_service.is_enrolled(device_id).await {
                    Ok(true) => return Ok(()),
                    Ok(false) => warn!("device is not enrolled on server yet"),
                    Err(err) => warn!("failed to verify enrollment: {err:#}"),
                }
            } else {
                warn!("server health check failed");
            }

            info!("retrying enrollment check in {:?}", delay);
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = sleep(delay) => {}
            }
            delay = (delay * 2).min(constants::RETRY_MAX_DELAY);
        }
    }

    async fn bootstrap_tokens(&self) -> Result<Tokens> {
        if let Some(refresh_token) = self.auth_service.load_refresh_token()? {
            match self.auth_service.refresh_tokens(&refresh_token).await {
                Ok(tokens) => {
                    self.auth_service.save_refresh_token(&tokens.refresh_token)?;
                    return Ok(tokens);
                }
                Err(err) => warn!("token refresh failed, falling back to recover: {err:#}"),
            }
        } else {
            info!("refresh token not found, attempting recover flow");
        }

        let tokens = self.auth_service.recover_tokens().await?;
        self.auth_service.save_refresh_token(&tokens.refresh_token)?;
        Ok(tokens)
    }
}

async fn sync_loop(
    http: Arc<AuthenticatedHttpClient>,
    system_info: Arc<dyn SystemInfoProvider>,
    server_url: String,
    shutdown: CancellationToken,
) -> Result<()> {
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        match build_computer_payload(system_info.as_ref()) {
            Ok(payload) => {
                let url = format!("{server_url}/computer/rustdesk-sync");
                match http.patch_json(&url, serde_json::to_value(payload)?).await {
                    Ok(resp) if resp.status().is_success() => info!("rustdesk sync completed"),
                    Ok(resp) => warn!("rustdesk sync failed with status {}", resp.status()),
                    Err(err) => error!("rustdesk sync request failed: {err:#}"),
                }
            }
            Err(err) => error!("failed to collect system info: {err:#}"),
        }

        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            _ = sleep(constants::RUSTDESK_SYNC_INTERVAL) => {}
        }
    }
}

async fn task_loop(
    http: Arc<AuthenticatedHttpClient>,
    process_runner: Arc<dyn ProcessRunner>,
    server_url: String,
    shutdown: CancellationToken,
) -> Result<()> {
    loop {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        let url = format!("{server_url}/tasks");
        match http.get(&url).await {
            Ok(resp) if resp.status().is_success() => match resp.json::<TaskListResponse>().await {
                Ok(payload) => {
                    for task in payload.tasks {
                        if let Err(err) =
                            handle_task(&task, http.as_ref(), process_runner.as_ref(), &server_url).await
                        {
                            error!("task {} failed: {err:#}", task.id);
                        }
                    }
                }
                Err(err) => error!("failed to decode tasks payload: {err:#}"),
            },
            Ok(resp) => warn!("task polling failed with status {}", resp.status()),
            Err(err) => error!("task polling request failed: {err:#}"),
        }

        tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            _ = sleep(constants::TASK_LOOP_INTERVAL) => {}
        }
    }
}

fn build_computer_payload(system_info: &dyn SystemInfoProvider) -> Result<ComputerPayload> {
    Ok(ComputerPayload {
        name: system_info.computer_name()?,
        rustdesk_id: system_info.rustdesk_id()?,
        ip: system_info.computer_ip().unwrap_or_default(),
        os: system_info.os_caption().unwrap_or_default(),
        os_version: system_info.os_version().unwrap_or_default(),
        login_user: system_info.current_user().unwrap_or_default(),
        intune_id: system_info.intune_id().unwrap_or_default(),
        last_connection: Utc::now().to_rfc3339(),
    })
}

async fn handle_task(
    task: &TaskEnvelope,
    http: &AuthenticatedHttpClient,
    process_runner: &dyn ProcessRunner,
    server_url: &str,
) -> Result<()> {
    match task.task.as_str() {
        "SET_PASSWD" => {
            set_task_status(http, server_url, &task.id, "IN_PROGRESS", "").await?;
            let payload: SetPasswordTask = serde_json::from_value(task.task_data.clone())?;
            let result = process_runner.run(
                r"C:\Program Files\RustDesk\RustDesk.exe",
                &["--password", payload.password.as_str()],
                Duration::from_secs(300),
                None,
            );
            finish_task(server_url, http, &task.id, result).await?;
        }
        "SET_NETWORK_STRING" => {
            set_task_status(http, server_url, &task.id, "IN_PROGRESS", "").await?;
            let payload: SetNetworkStringTask = serde_json::from_value(task.task_data.clone())?;
            let clean = payload.network_string.trim_start_matches('=').to_string();
            let result = process_runner.run(
                r"C:\Program Files\RustDesk\RustDesk.exe",
                &["--config", clean.as_str()],
                Duration::from_secs(300),
                None,
            );
            finish_task(server_url, http, &task.id, result).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn finish_task(
    server_url: &str,
    http: &AuthenticatedHttpClient,
    task_id: &str,
    result: Result<crate::traits::ProcessOutput>,
) -> Result<()> {
    match result {
        Ok(output) if output.status_code == 0 => {
            set_task_status(http, server_url, task_id, "SUCCESS", "").await?;
        }
        Ok(output) => {
            let message = format!("exit code {}: {}", output.status_code, output.stderr);
            set_task_status(http, server_url, task_id, "ERROR", &message).await?;
        }
        Err(err) => {
            set_task_status(http, server_url, task_id, "ERROR", &err.to_string()).await?;
        }
    }
    Ok(())
}

async fn set_task_status(
    http: &AuthenticatedHttpClient,
    server_url: &str,
    task_id: &str,
    status: &str,
    error_message: &str,
) -> Result<()> {
    let url = format!("{server_url}/task/{task_id}");
    let response = http
        .patch_json(
            &url,
            json!({
                "status": status,
                "error": error_message,
            }),
        )
        .await?;
    if !response.status().is_success() {
        warn!("failed to set task {task_id} status to {status}: {}", response.status());
    }
    Ok(())
}
