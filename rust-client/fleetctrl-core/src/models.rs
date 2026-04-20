use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enrollment {
    pub tokens: Tokens,
    pub device_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputerPayload {
    pub name: String,
    pub rustdesk_id: String,
    pub ip: String,
    pub os: String,
    pub os_version: String,
    pub login_user: String,
    pub intune_id: String,
    pub last_connection: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub id: String,
    pub status: String,
    pub task: String,
    pub task_data: Value,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskListResponse {
    pub tasks: Vec<TaskEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetPasswordTask {
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetNetworkStringTask {
    #[serde(rename = "networkString")]
    pub network_string: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateInfo {
    pub version: String,
    pub id: String,
    pub hash: String,
}
