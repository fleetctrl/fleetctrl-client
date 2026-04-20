use crate::{
    constants,
    dpop::{compute_jkt, create_dpop, generate_private_jwk, StoredJwk},
    models::{Enrollment, Tokens},
    traits::{RegistryStore, SecretStore},
    update::Updater,
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
    Client, Method, Response,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::Mutex as AsyncMutex, time::sleep};
use tracing::{info, warn};

pub struct AuthService {
    server_url: String,
    client: Client,
    secret_store: Arc<dyn SecretStore>,
    registry: Arc<dyn RegistryStore>,
    server_skew: Mutex<Duration>,
}

impl AuthService {
    pub fn new(
        server_url: String,
        client: Client,
        secret_store: Arc<dyn SecretStore>,
        registry: Arc<dyn RegistryStore>,
    ) -> Self {
        Self {
            server_url,
            client,
            secret_store,
            registry,
            server_skew: Mutex::new(Duration::ZERO),
        }
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn load_device_id(&self) -> Result<Option<String>> {
        Ok(self
            .registry
            .get_string(constants::REGISTRY_ROOT_KEY, constants::DEVICE_ID_VALUE_NAME)?
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()))
    }

    pub fn save_device_id(&self, device_id: &str) -> Result<()> {
        self.registry.set_string(
            constants::REGISTRY_ROOT_KEY,
            constants::DEVICE_ID_VALUE_NAME,
            device_id.trim(),
        )
    }

    pub fn load_refresh_token(&self) -> Result<Option<String>> {
        self.read_secret_string(Path::new(&constants::refresh_token_path()))
            .map(Some)
            .or_else(|err| {
                if is_not_found(&err) {
                    Ok(None)
                } else {
                    Err(err)
                }
            })
    }

    pub fn save_refresh_token(&self, token: &str) -> Result<()> {
        self.write_secret_string(Path::new(&constants::refresh_token_path()), token)
    }

    pub fn load_private_jwk(&self) -> Result<StoredJwk> {
        let bytes = self.secret_store.load_machine_secret(Path::new(&constants::private_jwk_path()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_private_jwk(&self, jwk: &StoredJwk) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(jwk)?;
        self.secret_store
            .save_machine_secret(Path::new(&constants::private_jwk_path()), &bytes)
    }

    pub fn private_jwk_exists(&self) -> bool {
        Path::new(&constants::private_jwk_path()).exists()
    }

    pub async fn healthcheck_once(&self) -> Result<bool> {
        let response = self
            .client
            .get(format!("{}/health", self.server_url))
            .timeout(constants::HEALTH_TIMEOUT)
            .send()
            .await;
        match response {
            Ok(resp) => {
                self.update_server_skew_from_date_header(resp.headers().get("date").and_then(|value| value.to_str().ok()));
                Ok(resp.status().is_success())
            }
            Err(_) => Ok(false),
        }
    }

    pub async fn enroll(&self, enroll_token: &str, computer_name: &str) -> Result<Enrollment> {
        let jwk = generate_private_jwk()?;
        let jkt = compute_jkt(&jwk.x, &jwk.y)?;
        self.save_private_jwk(&jwk)?;

        #[derive(Deserialize)]
        struct EnrollResponse {
            tokens: Tokens,
            device_id: String,
        }

        let response = self
            .client
            .post(format!("{}/enroll", self.server_url))
            .header("Content-Type", "application/json")
            .header("enrollment-token", enroll_token.trim())
            .json(&json!({
                "name": computer_name,
                "jkt": jkt,
            }))
            .send()
            .await?;

        if response.status().as_u16() != 201 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("enroll failed with status {status}: {body}"));
        }

        let payload: EnrollResponse = response.json().await?;
        Ok(Enrollment {
            tokens: payload.tokens,
            device_id: payload.device_id.trim().to_string(),
        })
    }

    pub async fn is_enrolled(&self, device_id: &str) -> Result<bool> {
        let response = self
            .client
            .get(format!("{}/devices/{}/is-enrolled", self.server_url, device_id.trim()))
            .header("Content-Type", "application/json")
            .send()
            .await?;
        Ok(response.status().is_success())
    }

    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<Tokens> {
        #[derive(Deserialize)]
        struct RefreshResponse {
            tokens: Tokens,
        }

        self.sync_server_skew().await;
        let proof = self.build_dpop("POST", &format!("{}/token/refresh", self.server_url), Some(""))?;
        let response = self
            .client
            .post(format!("{}/token/refresh", self.server_url))
            .header("Content-Type", "application/json")
            .header("DPoP", proof)
            .json(&json!({ "refresh_token": refresh_token }))
            .send()
            .await?;

        if response.status().as_u16() == 401 {
            return Err(anyhow!("invalid refresh token"));
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("token refresh failed with status {status}: {body}"));
        }

        Ok(response.json::<RefreshResponse>().await?.tokens)
    }

    pub async fn recover_tokens(&self) -> Result<Tokens> {
        #[derive(Deserialize)]
        struct RecoverResponse {
            tokens: Tokens,
        }

        self.sync_server_skew().await;
        let proof = self.build_dpop("POST", &format!("{}/token/recover", self.server_url), None)?;
        let response = self
            .client
            .post(format!("{}/token/recover", self.server_url))
            .header("Content-Type", "application/json")
            .header("DPoP", proof)
            .json(&json!({}))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("token recovery failed with status {status}: {body}"));
        }

        Ok(response.json::<RecoverResponse>().await?.tokens)
    }

    pub fn current_dpop_issued_at_unix(&self) -> i64 {
        let skew = *self.server_skew.lock().expect("server skew mutex poisoned");
        (Utc::now() - chrono::Duration::from_std(skew).unwrap_or_default()).timestamp()
    }

    pub fn update_server_skew_from_date_header(&self, date_header: Option<&str>) {
        let Some(date_header) = date_header else {
            return;
        };
        if let Ok(server_time) = httpdate::parse_http_date(date_header) {
            let skew = std::time::SystemTime::now()
                .duration_since(server_time)
                .unwrap_or_default();
            *self.server_skew.lock().expect("server skew mutex poisoned") = skew;
        }
    }

    pub async fn sync_server_skew(&self) {
        let response = self
            .client
            .get(format!("{}/health", self.server_url))
            .timeout(constants::HEALTH_TIMEOUT)
            .send()
            .await;
        if let Ok(resp) = response {
            self.update_server_skew_from_date_header(resp.headers().get("date").and_then(|value| value.to_str().ok()));
        }
    }

    pub fn build_dpop(&self, method: &str, url: &str, access_token: Option<&str>) -> Result<String> {
        let jwk = self.load_private_jwk()?;
        let issued_at = self.current_dpop_issued_at_unix();
        Ok(create_dpop(method, url, access_token, issued_at, &jwk)?.0)
    }

    fn write_secret_string(&self, path: &Path, value: &str) -> Result<()> {
        self.secret_store.save_machine_secret(path, value.as_bytes())
    }

    fn read_secret_string(&self, path: &Path) -> Result<String> {
        let bytes = self.secret_store.load_machine_secret(path)?;
        Ok(String::from_utf8(bytes)?)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RefreshState {
    pub last_attempt: Option<Instant>,
    pub backoff: Duration,
}

pub struct AuthenticatedHttpClient {
    client: Client,
    auth_service: Arc<AuthService>,
    registry: Arc<dyn RegistryStore>,
    tokens: AsyncMutex<Tokens>,
    refresh_lock: AsyncMutex<()>,
    refresh_state: AsyncMutex<RefreshState>,
    updater: Option<Arc<Updater>>,
}

impl AuthenticatedHttpClient {
    pub fn new(
        client: Client,
        auth_service: Arc<AuthService>,
        registry: Arc<dyn RegistryStore>,
        updater: Option<Arc<Updater>>,
    ) -> Self {
        Self {
            client,
            auth_service,
            registry,
            tokens: AsyncMutex::new(Tokens::default()),
            refresh_lock: AsyncMutex::new(()),
            refresh_state: AsyncMutex::new(RefreshState::default()),
            updater,
        }
    }

    pub async fn set_tokens(&self, tokens: Tokens) {
        *self.tokens.lock().await = tokens;
    }

    pub async fn current_tokens(&self) -> Tokens {
        self.tokens.lock().await.clone()
    }

    pub async fn get(&self, url: &str) -> Result<Response> {
        self.send_json(Method::GET, url, None, HeaderMap::new(), false).await
    }

    pub async fn post_json(&self, url: &str, body: Value) -> Result<Response> {
        self.send_json(Method::POST, url, Some(body), HeaderMap::new(), false).await
    }

    pub async fn patch_json(&self, url: &str, body: Value) -> Result<Response> {
        self.send_json(Method::PATCH, url, Some(body), HeaderMap::new(), false).await
    }

    pub async fn send_json(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
        extra_headers: HeaderMap,
        bypass_auth: bool,
    ) -> Result<Response> {
        let should_bypass = bypass_auth || is_bypassed_path(url);
        if !should_bypass {
            self.wait_for_server_online().await?;
        }

        let response = self
            .execute(method.clone(), url, body.clone(), extra_headers.clone(), should_bypass)
            .await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED || should_bypass {
            return Ok(response);
        }

        self.ensure_fresh_tokens().await?;
        self.execute(method, url, body, extra_headers, should_bypass).await
    }

    async fn execute(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
        extra_headers: HeaderMap,
        bypass_auth: bool,
    ) -> Result<Response> {
        let mut headers = extra_headers;
        headers.insert("X-Client-Version", HeaderValue::from_static(constants::VERSION));
        headers.insert(
            "X-Client-Platform",
            HeaderValue::from_str(&self.client_platform()?)?,
        );

        let mut builder = self.client.request(method.clone(), url).headers(headers);
        if let Some(body) = body.as_ref() {
            builder = builder.json(body);
        }

        if !bypass_auth {
            let tokens = self.tokens.lock().await.clone();
            if !tokens.access_token.is_empty() {
                builder = builder.header(AUTHORIZATION, format!("Bearer {}", tokens.access_token));
                builder = builder.header(
                    "DPoP",
                    self.auth_service
                        .build_dpop(method.as_str(), url, Some(&tokens.access_token))?,
                );
            }
        }

        let response = builder.send().await?;
        self.auth_service.update_server_skew_from_date_header(
            response.headers().get("date").and_then(|value| value.to_str().ok()),
        );
        if response.status().is_success() {
            if let Some(updater) = &self.updater {
                updater.process_response(&response).await;
            }
        }
        Ok(response)
    }

    async fn wait_for_server_online(&self) -> Result<()> {
        loop {
            if self.auth_service.healthcheck_once().await? {
                return Ok(());
            }
            warn!("server is unavailable, retrying in {:?}", constants::HEALTH_POLL_INTERVAL);
            sleep(constants::HEALTH_POLL_INTERVAL).await;
        }
    }

    async fn ensure_fresh_tokens(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        let current = self.tokens.lock().await.clone();
        if current.refresh_token.is_empty() {
            let recovered = self.auth_service.recover_tokens().await?;
            self.auth_service.save_refresh_token(&recovered.refresh_token)?;
            *self.tokens.lock().await = recovered;
            return Ok(());
        }

        {
            let state = self.refresh_state.lock().await.clone();
            if let Some(last_attempt) = state.last_attempt {
                if last_attempt.elapsed() < state.backoff {
                    let wait = state.backoff - last_attempt.elapsed();
                    info!("auth backoff active for {:?}", wait);
                    sleep(wait).await;
                }
            }
        }

        let refreshed = match self.auth_service.refresh_tokens(&current.refresh_token).await {
            Ok(tokens) => tokens,
            Err(refresh_err) => {
                warn!("token refresh failed: {refresh_err:#}; attempting recovery");
                self.auth_service.recover_tokens().await?
            }
        };

        self.auth_service.save_refresh_token(&refreshed.refresh_token)?;
        *self.tokens.lock().await = refreshed;
        *self.refresh_state.lock().await = RefreshState {
            last_attempt: Some(Instant::now()),
            backoff: Duration::ZERO,
        };
        Ok(())
    }

    fn client_platform(&self) -> Result<String> {
        if self
            .registry
            .get_u32(constants::REGISTRY_ROOT_KEY, constants::INSTALLED_VIA_MSI_VALUE_NAME)?
            .unwrap_or_default()
            > 0
        {
            Ok("windows-msi".to_string())
        } else {
            Ok("windows-exe".to_string())
        }
    }
}

fn is_bypassed_path(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(url) => url,
        Err(_) => return false,
    };
    match parsed.path() {
        "/health" | "/enroll" | "/token/refresh" | "/token/recover" => true,
        path if path.starts_with("/client/download/") => true,
        _ => false,
    }
}

fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .map(|value| value.kind() == std::io::ErrorKind::NotFound)
        .unwrap_or(false)
}
