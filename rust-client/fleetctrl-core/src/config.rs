use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallConfig {
    pub enroll_token: String,
    pub server_url: String,
    pub is_msi: bool,
    pub installer_log_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    Install(InstallConfig),
    Remove {
        delete_device_id: bool,
        installer_log_path: Option<String>,
    },
    Update {
        installer_log_path: Option<String>,
    },
    RunService,
}

pub fn normalize_server_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("server URL is required"));
    }

    let candidate = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    let mut url = Url::parse(&candidate)?;
    if url.host_str().is_none() {
        return Err(anyhow!("server URL is missing a host"));
    }
    if url.path() != "/" {
        let trimmed_path = url.path().trim_end_matches('/').to_string();
        url.set_path(&trimmed_path);
    } else {
        url.set_path("");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize_server_url;

    #[test]
    fn normalizes_missing_scheme() {
        let normalized = normalize_server_url("fleet.example.com/").unwrap();
        assert_eq!(normalized, "https://fleet.example.com");
    }

    #[test]
    fn strips_trailing_slashes() {
        let normalized = normalize_server_url("https://fleet.example.com/api///").unwrap();
        assert_eq!(normalized, "https://fleet.example.com/api");
    }

    #[test]
    fn rejects_empty_value() {
        assert!(normalize_server_url("   ").is_err());
    }
}
