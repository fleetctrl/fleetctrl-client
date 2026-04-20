use crate::{constants, models::UpdateInfo, traits::UpdateInstaller};
use anyhow::{anyhow, Result};
use reqwest::{header::CONTENT_TYPE, Client, Response};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use tokio::{fs, sync::Mutex};
use tracing::{error, info};

pub struct Updater {
    server_url: String,
    client: Client,
    installer: Arc<dyn UpdateInstaller>,
    updating: Mutex<bool>,
}

impl Updater {
    pub fn new(server_url: String, client: Client, installer: Arc<dyn UpdateInstaller>) -> Self {
        Self {
            server_url,
            client,
            installer,
            updating: Mutex::new(false),
        }
    }

    pub fn parse_header(resp: &Response) -> Result<Option<UpdateInfo>> {
        let value = match resp.headers().get("X-Client-Update") {
            Some(value) => value.to_str()?,
            None => return Ok(None),
        };
        let info: UpdateInfo = serde_json::from_str(value)?;
        if info.version == constants::VERSION {
            return Ok(None);
        }
        Ok(Some(info))
    }

    pub async fn process_response(self: &Arc<Self>, resp: &Response) {
        let info = match Self::parse_header(resp) {
            Ok(Some(info)) => info,
            Ok(None) => return,
            Err(err) => {
                error!("failed to parse X-Client-Update header: {err:#}");
                return;
            }
        };

        let mut guard = self.updating.lock().await;
        if *guard {
            return;
        }
        *guard = true;
        drop(guard);

        let this = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(err) = this.download_and_apply(&info).await {
                error!("update failed: {err:#}");
            }
            *this.updating.lock().await = false;
        });
    }

    async fn download_and_apply(&self, info: &UpdateInfo) -> Result<()> {
        info!("new version available: {} (current: {})", info.version, constants::VERSION);
        let download_url = format!("{}/client/download/{}", self.server_url, info.id);
        let resp = self.client.get(&download_url).send().await?.error_for_status()?;
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let extension = if content_type.contains("msi")
            || info.id.to_ascii_lowercase().ends_with(".msi")
            || self.installer.is_msi_installation()?
        {
            ".msi"
        } else {
            ".exe"
        };

        let bytes = resp.bytes().await?;
        let tmp_path = std::env::temp_dir().join(format!("fleetctrl-update-{}{}", info.version, extension));
        fs::write(&tmp_path, &bytes).await?;
        verify_hash(&tmp_path, &info.hash).await?;

        if extension == ".msi" {
            self.installer.apply_msi_update(&tmp_path)?;
        } else {
            self.installer.apply_exe_update(&tmp_path)?;
        }
        Ok(())
    }
}

pub async fn verify_hash(path: &PathBuf, expected_hash: &str) -> Result<()> {
    let bytes = fs::read(path).await?;
    let actual_hash = hex::encode(Sha256::digest(bytes));
    if !actual_hash.eq_ignore_ascii_case(expected_hash) {
        return Err(anyhow!(
            "hash mismatch: expected {expected_hash}, got {actual_hash}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Updater;
    use crate::models::UpdateInfo;
    use reqwest::header::HeaderValue;

    #[tokio::test]
    async fn parses_update_header() {
        let client = reqwest::Client::new();
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/health")
            .with_status(200)
            .with_header(
                "X-Client-Update",
                r#"{"version":"2.0.1","id":"abc","hash":"deadbeef"}"#,
            )
            .create();
        let resp = client.get(format!("{}/health", server.url())).send().await.unwrap();
        let parsed = Updater::parse_header(&resp).unwrap().unwrap();
        assert_eq!(
            parsed,
            UpdateInfo {
                version: "2.0.1".to_string(),
                id: "abc".to_string(),
                hash: "deadbeef".to_string()
            }
        );
        assert_eq!(
            HeaderValue::from_str(r#"{"version":"2.0.1","id":"abc","hash":"deadbeef"}"#)
                .unwrap()
                .to_str()
                .unwrap(),
            r#"{"version":"2.0.1","id":"abc","hash":"deadbeef"}"#
        );
    }
}
