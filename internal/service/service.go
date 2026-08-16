package service

import (
	"KiskaLE/RustDesk-ID/internal/apps"
	"KiskaLE/RustDesk-ID/internal/auth"
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"time"
)

type ApplicationManager interface {
	IsInstalled(ctx context.Context, release models.AssignedRelease, serverURL string) (bool, error)
	Install(ctx context.Context, release models.AssignedRelease, serverURL string) error
	Uninstall(ctx context.Context, release models.AssignedRelease, serverURL string) error
	SupportsUpgrade(ctx context.Context, release models.AssignedRelease, serverURL string) bool
	Upgrade(ctx context.Context, release models.AssignedRelease, serverURL string) error
}

type MainService struct {
	as        *auth.AuthService
	serverURL string
	Tokens    *auth.Tokens
	apps      ApplicationManager
}

func NewMainService(as *auth.AuthService, serverURL string, appManager ApplicationManager) *MainService {
	if appManager == nil {
		appManager = apps.NewManager()
	}

	return &MainService{as: as, serverURL: serverURL, apps: appManager}
}

func (ms *MainService) StartRustDeskServerTasks() {
	const sleepTime = 5 * time.Minute

	utils.Info("Starting tasks...")
	for {
		// get tasks
		tasksRes, err := utils.Get(ms.serverURL+"/tasks", map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			utils.Error(err)
			time.Sleep(sleepTime)
			continue
		}
		if tasksRes.StatusCode != 200 {
			// parse body
			utils.Error("Server returned error: ", utils.ParseHttpError(tasksRes))
			time.Sleep(sleepTime)
			continue
		}

		var data models.TaskResponse
		if err := json.NewDecoder(tasksRes.Body).Decode(&data); err != nil {
			tasksRes.Body.Close()
			utils.Error(err)
			time.Sleep(sleepTime)
			continue
		}
		tasksRes.Body.Close()
		tasksList := data.Tasks

		if len(tasksList) == 0 {
			utils.Info("No pending tasks found")
			time.Sleep(sleepTime)
			continue
		}

		for i := range tasksList {
			task := tasksList[i]
			switch task.Task {
			case "SET_PASSWD":
				// set task started
				if patchRes, patchErr := utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "IN_PROGRESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				}); patchErr == nil && patchRes != nil {
					patchRes.Body.Close()
				}
				var d models.SetPasswordTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					utils.Error(err)
					continue
				}

				// set password using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--password", d.Password)
				cmd.Stdout = log.Writer()
				cmd.Stderr = log.Writer()
				err := cmd.Run()
				if err != nil {
					utils.Error(err)
					if patchRes, patchErr := utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
						"status": "ERROR",
						"error":  err.Error(),
					}, map[string]string{
						"Content-Type": "application/json",
					}); patchErr == nil && patchRes != nil {
						patchRes.Body.Close()
					}
					break
				}
				utils.Info("Password set")

				if patchRes, patchErr := utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "SUCCESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				}); patchErr == nil && patchRes != nil {
					patchRes.Body.Close()
				}

			case "SET_NETWORK_STRING":
				// set task started
				if patchRes, patchErr := utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "IN_PROGRESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				}); patchErr == nil && patchRes != nil {
					patchRes.Body.Close()
				}
				var d models.SetNetworkStringTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					log.Println(err)
					continue
				}
				cleanString := strings.TrimLeft(d.NetworkString, "=")
				// set network using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--config", cleanString)
				cmd.Stdout = log.Writer()
				cmd.Stderr = log.Writer()
				err := cmd.Run()
				if err != nil {
					log.Println(err)
					if patchRes, patchErr := utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
						"status": "ERROR",
						"error":  err.Error(),
					}, map[string]string{
						"Content-Type": "application/json",
					}); patchErr == nil && patchRes != nil {
						patchRes.Body.Close()
					}
					break
				}
				utils.Info("Network string set")

				if patchRes, patchErr := utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "SUCCESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				}); patchErr == nil && patchRes != nil {
					patchRes.Body.Close()
				}

			}
		}

		time.Sleep(sleepTime)
	}
}

func nowUnixMilliPtr() *int64 {
	ts := time.Now().UnixMilli()
	return &ts
}

func (ms *MainService) reportReleaseInstallState(releaseID string, status apps.ReleaseInstallStateStatus, installedAt *int64) {
	if releaseID == "" {
		return
	}

	lastSeenAt := time.Now().UnixMilli()
	if err := apps.ReportReleaseInstallState(ms.serverURL, releaseID, status, installedAt, &lastSeenAt); err != nil {
		utils.Errorf("Failed to report install state %s for release %s: %v", status, releaseID, err)
	}
}

func (ms *MainService) GetAuthService() *auth.AuthService {
	return ms.as
}
