package service

import (
	"KiskaLE/RustDesk-ID/internal/apps"
	"KiskaLE/RustDesk-ID/internal/auth"
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

		computer := models.Computer{
			Name:           computerName,
			RustdeskID:     rustdeskID,
			IP:             computerIP,
			OS:             osName,
			OSVersion:      osVersion,
			LoginUser:      loginUser,
			LastConnection: time.Now().Format(time.RFC3339),
		}

		res, err := utils.Patch(ms.serverURL+"/computer/rustdesk-sync", map[string]string{
			"name":            computer.Name,
			"rustdesk_id":     computer.RustdeskID,
			"ip":              computer.IP,
			"os":              computer.OS,
			"os_version":      computer.OSVersion,
			"login_user":      computer.LoginUser,
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
			time.Sleep(15 * time.Minute)
			continue
		}
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
			utils.Error(err)
			time.Sleep(5 * time.Minute)
			continue
		}
		tasksList := data.Tasks

		for i := range tasksList {
			task := tasksList[i]
			switch task.Task {
			case "SET_PASSWD":
				// set task started
				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "IN_PROGRESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})
				var d models.SetPasswordTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					log.Println(err)
				}

				// set passwor using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--password", d.Password)
				cmd.Stdout = log.Writer()
				cmd.Stderr = log.Writer()
				err := cmd.Run()
				if err != nil {
					log.Println(err)
					utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
						"status": "ERROR",
						"error":  err.Error(),
					}, map[string]string{
						"Content-Type": "application/json",
					})
					break
				}
				utils.Info("Password set")

				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "SUCCESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})

			case "SET_NETWORK_STRING":
				// set task started
				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "IN_PROGRESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})
				var d models.SetNetworkStringTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					log.Println(err)
				}
				cleanString := strings.TrimLeft(d.NetworkString, "=")
				// set network using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--config", cleanString)
				cmd.Stdout = log.Writer()
				cmd.Stderr = log.Writer()
				err := cmd.Run()
				if err != nil {
					log.Println(err)
					utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
						"status": "ERROR",
						"error":  err.Error(),
					}, map[string]string{
						"Content-Type": "application/json",
					})
					break
				}
				utils.Info("Network string set")

				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "SUCCESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})

			}
		}

		time.Sleep(5 * time.Minute)
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
			time.Sleep(15 * time.Minute)
			continue
		}

		var assignedAppsResponse models.AssignedAppsResponse
		if err := json.NewDecoder(appsResponse.Body).Decode(&assignedAppsResponse); err != nil {
			utils.Error(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		for _, app := range assignedAppsResponse.Apps {
			utils.Info("Processing app: ", app.DisplayName)
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
					continue
				}
				if installed {
					if newestRelease.InstallerType == "winget" && newestRelease.Winget != nil && app.AutoUpdate {
						utils.Infof("Checking for updates for winget app %s...", newestRelease.Winget.WingetID)
						if err := apps.UpgradeApp(newestRelease); err != nil {
							utils.Errorf("Failed to upgrade winget app %s: %v", newestRelease.Winget.WingetID, err)
						}
					}
					continue
				}

				// application is not installed
				// install application
				if newestRelease.UninstallPrevious {
					// uninstall previous versions
					for _, release := range app.Releases {
						if release.Version == newestRelease.Version {
							continue
						}
						if err != nil {
							utils.Error(err)
							continue
						}
						if installed {
							utils.Info("Previous version is installed, uninstalling...")
							if err := apps.UninstallApp(release, ms.serverURL); err != nil {
								utils.Errorf("Failed to uninstall previous version: %v", err)
							}
							break
						}
					}
				}

				err = apps.InstallApp(newestRelease, ms.serverURL)
				if err != nil {
					utils.Errorf("Failed to install app: %v", err)
				}

			case "uninstall":
				// check if application is unisntalled
				installed, err := apps.IsAppInstalled(newestRelease)
				if err != nil {
					log.Println(err)
					continue
				}
				if !installed {
					continue
				}

				// application is installed
				// uninstall application
				for _, release := range app.Releases {
					if err != nil {
						utils.Error(err)
						continue
					}
					if installed {
						log.Println("Previous version is installed, uninstalling...")
						if err := apps.UninstallApp(release, ms.serverURL); err != nil {
							log.Printf("Failed to uninstall previous version: %v", err)
						}
						break
					}
				}
			}
		}

		time.Sleep(15 * time.Minute)
	}

}

func (ms *MainService) GetAuthService() *auth.AuthService {
	return ms.as
}
