package main

import (
	"KiskaLE/RustDesk-ID/internal/auth"
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/utils"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

type serviceHandler struct {
	ms *MainService
}

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
	TimeoutSeconds int64  `json:"timeout_seconds"`
	RunAsSystem    bool   `json:"run_as_system"`
	StoragePath    string `json:"storage_path"`
	Hash           string `json:"hash"`
	Bucket         string `json:"bucket"`
	ByteSize       int64  `json:"byte_size"`
}

type AssignedRelease struct {
	ID             string               `json:"id"`
	Version        string               `json:"version"`
	AssignType     string               `json:"assign_type"`
	Action         string               `json:"action"`
	InstallerType  string               `json:"installer_type"`
	Win32          *Win32Release        `json:"win32,omitempty"`
	Winget         *WingetRelease       `json:"winget,omitempty"`
	DetectionRules []DetectionRule      `json:"detection_rules,omitempty"`
	Requirements   []ReleaseRequirement `json:"requirements,omitempty"`
}

type AssignedApp struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Publisher   string            `json:"publisher"`
	Releases    []AssignedRelease `json:"releases"`
}

type MainService struct {
	as        *auth.AuthService
	serverURL string
	tokens    *auth.Tokens
}

func NewMainService(as *auth.AuthService, serverURL string) *MainService {
	return &MainService{as: as, serverURL: serverURL}
}

func (ms *MainService) startRustDeskServerSync() {
	fmt.Println("Starting RustDesk sync...")
	for {
		// get rustdesk ID
		rustdeskID, err := utils.GetRustDeskID()
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		// get PC name
		computerName, err := utils.GetComputerName()
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}
		// get PC IP
		computerIP, err := utils.GetComputerIP()
		if err != nil {
			log.Println(err)
		}
		// get OS
		os, err := utils.GetComputerOS()
		if err != nil {
			log.Println(err)
		}
		// get OS version
		osVersion, err := utils.GetComputerOSVersion()
		if err != nil {
			log.Println(err)
		}

		loginUser, err := utils.GetCurrentUser()
		if err != nil {
			log.Println(err)
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

		computer := Computer{
			Name:           computerName,
			RustdeskID:     rustdeskID,
			IP:             computerIP,
			OS:             os,
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
			log.Println("Server returned status code: ", utils.ParseHttpError(res))
			time.Sleep(15 * time.Minute)
			continue
		}
		time.Sleep(5 * time.Minute)
	}
}

func (ms *MainService) startRustDeskServerTasks() {
	log.Println("Starting tasks...")
	for {
		type TaskResponse struct {
			Tasks []Task `json:"tasks"`
		}

		// get tasks
		tasksRes, err := utils.Get(ms.serverURL+"/tasks", map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			log.Println(err)
			time.Sleep(5 * time.Minute)
			continue
		}
		if tasksRes.StatusCode != 200 {
			// parse body
			log.Println("Server returned error: ", utils.ParseHttpError(tasksRes))
			time.Sleep(5 * time.Minute)
			continue
		}

		var data TaskResponse
		if err := json.NewDecoder(tasksRes.Body).Decode(&data); err != nil {
			log.Println(err)
			time.Sleep(5 * time.Minute)
			continue
		}
		tasks := data.Tasks

		for i := range tasks {
			task := tasks[i]
			switch task.Task {
			case "SET_PASSWD":
				// set task started
				utils.Patch(ms.serverURL+"/task/"+task.ID, map[string]string{
					"status": "IN_PROGRESS",
					"error":  "",
				}, map[string]string{
					"Content-Type": "application/json",
				})
				var d SetPasswordTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					log.Println(err)
				}

				// set passwor using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--password", d.Password)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
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
				log.Println("Password set")

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
				var d SetNetworkStringTask
				if err := json.Unmarshal(task.TaskData, &d); err != nil {
					log.Println(err)
				}
				cleanString := strings.TrimLeft(d.NetworkString, "=")
				// set network using powershell
				cmd := exec.Command("C:\\Program Files\\RustDesk\\RustDesk.exe", "--config", cleanString)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
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
				log.Println("Network string set")

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

func (ms *MainService) startApplicationsManagement() {
	log.Println("Starting applications management...")
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
			log.Println("Server returned error: ", appsResponse.StatusCode)
			time.Sleep(15 * time.Minute)
			continue
		}
		type AssignedAppsResponse struct {
			Apps []AssignedApp `json:"apps"`
		}
		var assignedAppsResponse AssignedAppsResponse
		if err := json.NewDecoder(appsResponse.Body).Decode(&assignedAppsResponse); err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		for _, app := range assignedAppsResponse.Apps {
			newestRelease := app.Releases[0]
			switch newestRelease.AssignType {
			case "install":
				// check if application is installed
			case "uninstall":
				// check if application is unisntalled
			}
		}

		time.Sleep(15 * time.Minute)
	}

}

func isAppInstalled(appName string, detectionType string) (bool, error) {
	switch detectionType {
	case "winget":

	case "win32":

	}
	return false, nil
}

func (s *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	// Mark service as running and accept Stop/Shutdown
	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
	if err != nil {
		log.Fatalln("error getting key from registry: ", err)
	}

	for {
		ok, err := utils.Ping(serverURL)
		if err == nil && ok {
			break
		}

		// wait briefly, but allow Stop/Shutdown
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			case svc.Interrogate:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case <-time.After(5 * time.Second): // instead of 5 minutes; exponential backoff could be better
		}
	}

	// check if computer is enrolled

	as := auth.NewAuthService(serverURL)
	ms := NewMainService(as, serverURL)

	// check if computer is registered
	registered, err := ms.as.IsEnrolled()
	if err != nil {
		log.Fatalf("error during registration check: %v", err)
	}
	if !registered {
		log.Fatalln("This computer is not registered on the server.")
	}

	fmt.Println("Is computer registered: ", registered)
	var tokens auth.Tokens

	// load refresh token and refresh access token
	if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
		if nt, rerr := ms.as.RefreshTokens(rt); rerr == nil {
			tokens = nt
			// uložit nový refresh token po rotaci
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("warning: failed to save refresh token after refresh:", err)
			}
		} else {
			log.Println("token refresh failed, trying recover:", rerr)
			if nt, rerr2 := ms.as.RecoverTokens(); rerr2 == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("warning: failed to save refresh token after recover:", err)
				}
			} else {
				log.Println("token recover failed:", rerr2)
			}
		}
	} else {
		log.Println("refresh token not found, attempting recover without refresh token")
		if nt, rerr := ms.as.RecoverTokens(); rerr == nil {
			tokens = nt
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("warning: failed to save refresh token after recover:", err)
			}
		} else {
			log.Println("token recover failed:", rerr)
		}
	}

	ms.tokens = &tokens

	// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
	auth.InitHTTPClient(ms.as, ms.tokens, func(nt auth.Tokens) {
		if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
			log.Println("error saving refresh token after refresh:", err)
		}
	})

	go ms.startRustDeskServerSync()
	go ms.startRustDeskServerTasks()
	go ms.startApplicationsManagement()

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// Windows shell sometimes requests status
				changes <- svc.Status{
					State:   svc.Running,
					Accepts: svc.AcceptStop | svc.AcceptShutdown,
				}
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			default:
				// ignore other commands
				log.Printf("Unknown service command: %d", c.Cmd)
			}
		case <-ticker.C:
			// do nothing
		}
	}
}

func main() {

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			installCmd := flag.NewFlagSet("install", flag.ExitOnError)
			enrollToken := installCmd.String("token", "", "Enrollment token")
			serverURL := installCmd.String("url", "", "Server URL")

			err := installCmd.Parse(os.Args[2:])
			if err != nil {
				log.Fatal(err)
			}

			if *enrollToken == "" || *serverURL == "" {
				log.Fatalln("missing --token or --url")
			}

			err = InstallService(*enrollToken, *serverURL)
			if err != nil {
				panic(err)
			}
			return
		case "remove":
			err := RemoveService()
			if err != nil {
				panic(err)
			}
			return
		case "update":
			err := UpdateService()
			if err != nil {
				panic(err)
			}
			return
		}
	}

	// 1) open (or create) file for writing
	f, err := os.OpenFile(consts.TargetDir+`\client.log`,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, // append to end
		0o644)                               // perms rw-r-r
	if err != nil {
		log.Fatalf("failed to open log: %v", err)
	}
	defer f.Close()

	// 2) redirect logger output
	log.SetOutput(f)

	// 3) set format (date, time, file:line)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if !consts.Production {
		// initialize supabase client
		// for dev only
		// check if computer is enrolled

		serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
		if err != nil {
			log.Fatalln("error getting key from registry: ", err)
		}

		as := auth.NewAuthService(serverURL)
		ms := NewMainService(as, serverURL)

		// check if computer is registered
		registered, err := ms.as.IsEnrolled()
		if err != nil {
			log.Fatalf("chyba při kontrole registrace: %v", err)
		}

		if !registered {
			log.Fatalln("This computer is not registered on the server.")
		}

		var tokens auth.Tokens

		if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
			if nt, rerr := ms.as.RefreshTokens(rt); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("warning: failed to save refresh token after refresh:", err)
				}
			} else {
				log.Println("token refresh failed, trying recover:", rerr)
				if nt, rerr2 := ms.as.RecoverTokens(); rerr2 == nil {
					tokens = nt
					if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
						log.Println("warning: failed to save refresh token after recover:", err)
					}
				} else {
					log.Println("token recover failed:", rerr2)
				}
			}
		} else {
			log.Println("refresh token not found, attempting recover without refresh token")
			if nt, rerr := ms.as.RecoverTokens(); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("warning: failed to save refresh token after recover:", err)
				}
			} else {
				log.Println("token recover failed:", rerr)
			}
		}
		ms.tokens = &tokens

		// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
		auth.InitHTTPClient(ms.as, ms.tokens, func(nt auth.Tokens) {
			if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("error saving refresh token after refresh:", err)
			}
		})

		go ms.startRustDeskServerSync()
		go ms.startRustDeskServerTasks()
		for {
			time.Sleep(1 * time.Hour)
		}
	}

	if err := svc.Run(consts.ServiceName, &serviceHandler{}); err != nil {
		log.Fatalf("service error: %v", err)
	}
}
