package service

import (
	"KiskaLE/RustDesk-ID/internal/apps"
	"KiskaLE/RustDesk-ID/internal/auth"
	"KiskaLE/RustDesk-ID/internal/database"
	"KiskaLE/RustDesk-ID/internal/models"
	"KiskaLE/RustDesk-ID/internal/utils"
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"time"
)

type MainService struct {
	as        *auth.AuthService
	serverURL string
	Tokens    *auth.Tokens
}

func NewMainService(as *auth.AuthService, serverURL string) *MainService {
	return &MainService{as: as, serverURL: serverURL}
}

func (ms *MainService) StartRustDeskServerSync() {
	utils.Info("Starting RustDesk sync...")
	for {
		// get rustdesk ID
		rustdeskID, err := utils.GetRustDeskID()
		if err != nil {
			utils.Error(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		// get PC name
		computerName, err := utils.GetComputerName()
		if err != nil {
			utils.Error(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		// get PC IP
		computerIP, err := utils.GetComputerIP()
		if err != nil {
			utils.Error(err)
		}
		// get OS
		osName, err := utils.GetComputerOS()
		if err != nil {
			utils.Error(err)
		}
		// get OS version
		osVersion, err := utils.GetComputerOSVersion()
		if err != nil {
			utils.Error(err)
		}

		loginUser, err := utils.GetCurrentUser()
		if err != nil {
			utils.Error(err)
		}

		intuneID, err := utils.GetIntuneID()
		if err != nil {
			utils.Error(err)
		}

		computer := models.Computer{
			Name:           computerName,
			RustdeskID:     rustdeskID,
			IP:             computerIP,
			OS:             osName,
			OSVersion:      osVersion,
			LoginUser:      loginUser,
			IntuneID:       intuneID,
			LastConnection: time.Now().Format(time.RFC3339),
		}

		res, err := utils.Patch(ms.serverURL+"/computer/rustdesk-sync", map[string]string{
			"name":            computer.Name,
			"rustdesk_id":     computer.RustdeskID,
			"ip":              computer.IP,
			"os":              computer.OS,
			"os_version":      computer.OSVersion,
			"login_user":      computer.LoginUser,
			"intune_id":       computer.IntuneID,
			"last_connection": computer.LastConnection,
		}, map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		if res.StatusCode != 200 {
			// parse body
			utils.Error("Server returned status code: ", utils.ParseHttpError(res))
			res.Body.Close()
			time.Sleep(15 * time.Minute)
			continue
		}
		res.Body.Close()
		time.Sleep(5 * time.Minute)
	}
}

func (ms *MainService) StartRustDeskServerTasks() {
	utils.Info("Starting tasks...")
	for {
		// get tasks
		tasksRes, err := utils.Get(ms.serverURL+"/tasks", map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			utils.Error(err)
			time.Sleep(5 * time.Minute)
			continue
		}
		if tasksRes.StatusCode != 200 {
			// parse body
			utils.Error("Server returned error: ", utils.ParseHttpError(tasksRes))
			time.Sleep(5 * time.Minute)
			continue
		}

		var data models.TaskResponse
		if err := json.NewDecoder(tasksRes.Body).Decode(&data); err != nil {
			tasksRes.Body.Close()
			utils.Error(err)
			time.Sleep(5 * time.Minute)
			continue
		}
		tasksRes.Body.Close()
		tasksList := data.Tasks

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
					log.Println(err)
					continue
				}

				// set password using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--password", d.Password)
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

		time.Sleep(5 * time.Minute)
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

func (ms *MainService) StartApplicationsManagement() {
	utils.Info("Starting applications management...")

	for {
		// get asigned applications
		appsResponse, err := utils.Get(ms.serverURL+"/apps/assigned", map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		if appsResponse.StatusCode != 200 {
			// parse body
			utils.Error("Server returned error: ", appsResponse.StatusCode)
			appsResponse.Body.Close()
			time.Sleep(15 * time.Minute)
			continue
		}

		var assignedAppsResponse models.AssignedAppsResponse
		if err := json.NewDecoder(appsResponse.Body).Decode(&assignedAppsResponse); err != nil {
			utils.Error(err)
			appsResponse.Body.Close()
			time.Sleep(15 * time.Minute)
			continue
		}
		appsResponse.Body.Close()

		if len(assignedAppsResponse.Apps) == 0 {
			utils.Info("No assigned apps found")
			time.Sleep(15 * time.Minute)
			continue
		}

		for _, app := range assignedAppsResponse.Apps {
			utils.Info("Processing app: ", app.DisplayName)
			if len(app.Releases) == 0 {
				utils.Errorf("App %s has no releases, skipping", app.DisplayName)
				continue
			}
			newestRelease := app.Releases[len(app.Releases)-1]
			if newestRelease.AssignType == "exclude" {
				continue
			}

			switch newestRelease.Action {
			case "install":
				// check if application is installed
				installed, err := apps.IsAppInstalled(newestRelease)
				if err != nil {
					utils.Errorf("Failed to check if app is installed: %v", err)
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
					continue
				}

				if installed {
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateInstalled, nil)
					if newestRelease.InstallerType == "winget" && newestRelease.Winget != nil && app.AutoUpdate {
						// Check if we should check for updates (once per 24h)
						shouldCheck, err := database.ShouldCheckWinget(newestRelease.Winget.WingetID)
						if err != nil {
							utils.Errorf("Failed to check database for winget check time: %v", err)
							shouldCheck = true // Check anyway on error
						}

						if shouldCheck {
							utils.Infof("Checking for updates for winget app %s...", newestRelease.Winget.WingetID)
							if err := apps.UpgradeApp(newestRelease); err != nil {
								utils.Errorf("Failed to upgrade winget app %s: %v", newestRelease.Winget.WingetID, err)
							}
							// Mark as checked
							if err := database.UpdateWingetCheck(newestRelease.Winget.WingetID); err != nil {
								utils.Errorf("Failed to update winget check time in database: %v", err)
							}
						} else {
							utils.Infof("Skipping winget update check for %s (already checked in last 24h)", app.DisplayName)
						}
					}
					continue
				}

				// Check backoff for install
				shouldAttempt, err := database.ShouldAttemptApp(newestRelease.ID)
				if err != nil {
					utils.Errorf("Failed to check backoff: %v", err)
					shouldAttempt = true
				}
				if !shouldAttempt {
					utils.Infof("Skipping installation of %s due to backoff after multiple failures", app.DisplayName)
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
					continue
				}

				ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateInstalling, nil)

				// application is not installed
				// install application
				if newestRelease.UninstallPrevious {
					// uninstall previous versions
					for _, release := range app.Releases {
						if release.Version == newestRelease.Version {
							continue
						}

						// Check if this previous version is actually installed before uninstalling
						prevInstalled, prevErr := apps.IsAppInstalled(release)
						if prevErr != nil {
							utils.Errorf("Failed to check if previous version %s is installed: %v", release.Version, prevErr)
							continue
						}

						if prevInstalled {
							utils.Info("Previous version is installed, uninstalling...")

							// Check backoff for uninstall
							shouldAttempt, err := database.ShouldAttemptApp(release.ID)
							if err != nil {
								utils.Errorf("Failed to check backoff: %v", err)
								shouldAttempt = true
							}
							if !shouldAttempt {
								utils.Infof("Skipping uninstallation of previous version %s due to backoff after multiple failures", release.Version)
								continue
							}

							if err := apps.UninstallApp(release, ms.serverURL); err != nil {
								utils.Errorf("Failed to uninstall previous version: %v", err)
								database.RecordAppFailure(release.ID)
							} else {
								database.ResetAppFailures(release.ID)
							}
							break
						}
					}
				}

				err = apps.InstallApp(newestRelease, ms.serverURL)
				if err != nil {
					utils.Errorf("Failed to install app: %v", err)
					database.RecordAppFailure(newestRelease.ID)
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
				} else {
					database.ResetAppFailures(newestRelease.ID)
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateInstalled, nowUnixMilliPtr())
				}

				// check if app is installed
				installed, err = apps.IsAppInstalled(newestRelease)
				if err != nil {
					utils.Errorf("Failed to check if app is installed: %v", err)
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
					continue
				}
				if !installed {
					utils.Errorf("Unable to install application")
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
					continue
				}

			case "uninstall":
				// check if application is uninstalled
				installed, err := apps.IsAppInstalled(newestRelease)
				if err != nil {
					log.Println(err)
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
					continue
				}
				if !installed {
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateUninstalled, nil)
					continue
				}

				// application is installed — try to uninstall each release version that is present
				for _, release := range app.Releases {
					releaseInstalled, relErr := apps.IsAppInstalled(release)
					if relErr != nil {
						utils.Errorf("Failed to check if release %s is installed: %v", release.Version, relErr)
						continue
					}
					if !releaseInstalled {
						continue
					}

					utils.Infof("Version %s is installed, uninstalling...", release.Version)

					// Check backoff
					shouldAttempt, err := database.ShouldAttemptApp(release.ID)
					if err != nil {
						utils.Errorf("Failed to check backoff: %v", err)
						shouldAttempt = true
					}
					if !shouldAttempt {
						utils.Infof("Skipping uninstallation of %s due to backoff after multiple failures", app.DisplayName)
						continue
					}

					if err := apps.UninstallApp(release, ms.serverURL); err != nil {
						log.Printf("Failed to uninstall version %s: %v", release.Version, err)
						database.RecordAppFailure(release.ID)
						ms.reportReleaseInstallState(release.ID, apps.ReleaseInstallStateError, nil)
					} else {
						database.ResetAppFailures(release.ID)
						ms.reportReleaseInstallState(release.ID, apps.ReleaseInstallStateUninstalled, nil)
					}
					break
				}

				// check if application is uninstalled
				installed, err = apps.IsAppInstalled(newestRelease)
				if err != nil {
					utils.Errorf("Failed to check if app is installed: %v", err)
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
					continue
				}
				if installed {
					utils.Errorf("Unable to uninstall application")
					ms.reportReleaseInstallState(newestRelease.ID, apps.ReleaseInstallStateError, nil)
					continue
				}
			}
		}

		time.Sleep(15 * time.Minute)
	}

}

func (ms *MainService) GetAuthService() *auth.AuthService {
	return ms.as
}
