package models

import (
	"encoding/json"
	"time"
)

type Task struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Task      string          `json:"task"`
	TaskData  json.RawMessage `json:"task_data"`
	CreatedAt time.Time       `json:"created_at"`
}

type SetPasswordTask struct {
	Password string `json:"password"`
}

type SetNetworkStringTask struct {
	NetworkString string `json:"networkString"`
}

type Win32Release struct {
	InstallBinaryPath   string `json:"install_binary_path"`
	Hash                string `json:"hash"`
	InstallScript       string `json:"install_script"`
	UninstallScript     string `json:"uninstall_script"`
	InstallBinarySize   int64  `json:"install_binary_size"`
	InstallBinaryBucket string `json:"install_binary_bucket"`
}

type WingetRelease struct {
	WingetID string `json:"winget_id"`
}

type DetectionRule struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

type ReleaseRequirement struct {
	ID             string `json:"id"`
	TimeoutSeconds int64  `json:"timeout_seconds"`
	RunAsSystem    bool   `json:"run_as_system"`
	Hash           string `json:"hash"`
}

type AssignedRelease struct {
	ID                string               `json:"id"`
	Version           string               `json:"version"`
	AssignType        string               `json:"assign_type"`
	Action            string               `json:"action"`
	InstallerType     string               `json:"installer_type"`
	UninstallPrevious bool                 `json:"uninstall_previous"`
	Win32             *Win32Release        `json:"win32,omitempty"`
	Winget            *WingetRelease       `json:"winget,omitempty"`
	DetectionRules    []DetectionRule      `json:"detection_rules,omitempty"`
	Requirements      []ReleaseRequirement `json:"requirements,omitempty"`
}

type AssignedApp struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Publisher   string            `json:"publisher"`
	AutoUpdate  bool              `json:"auto_update"`
	Releases    []AssignedRelease `json:"releases"`
}

type AssignedAppsResponse struct {
	Apps []AssignedApp `json:"apps"`
}

type TaskResponse struct {
	Tasks []Task `json:"tasks"`
}

type Computer struct {
	Name           string `json:"name"`
	RustdeskID     string `json:"rustdesk_id"`
	IP             string `json:"ip"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	LoginUser      string `json:"login_user"`
	LastConnection string `json:"last_connection"`
}
