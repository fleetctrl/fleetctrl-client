package main

import (
	"KiskaLE/RustDesk-ID/internal/auth"
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/database"
	"KiskaLE/RustDesk-ID/internal/manager"
	"KiskaLE/RustDesk-ID/internal/registry"
	"KiskaLE/RustDesk-ID/internal/service"
	"KiskaLE/RustDesk-ID/internal/updater"
	"KiskaLE/RustDesk-ID/internal/utils"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	winreg "golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

type serviceHandler struct{}

func (s *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	// Mark service as running and accept Stop/Shutdown
	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	serverURL, err := registry.GetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
	if err != nil {
		log.Fatalln("error getting key from registry: ", err)
	}

	// Initialize services
	if err := database.Init(); err != nil {
		utils.Errorf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	as := auth.NewAuthService(serverURL)
	ms := service.NewMainService(as, serverURL)
	deviceID, hasDeviceID, err := auth.LoadDeviceID()
	if err != nil {
		log.Fatalln("error getting device ID from registry: ", err)
	}
	if !hasDeviceID {
		log.Fatalln("DeviceID is missing. Re-enroll or reinstall the client.")
	}

	var registered bool
	delay := 5 * time.Second
	const maxDelay = 15 * time.Minute

	// Connection and enrollment check loop with exponential backoff
	for {
		// Check connection
		ok, err := utils.Ping(serverURL)
		if err != nil {
			utils.Errorf("Ping error: %v", err)
		} else if !ok {
			utils.Info("Ping failed: server unhealthy")
		} else {
			// Connection is good, check enrollment
			registered, err = as.IsEnrolled(deviceID)
			if err == nil {
				// Success
				break
			}
			utils.Errorf("Error checking enrollment: %v", err)
		}

		utils.Infof("Retrying in %v...", delay)

		// wait with backoff, but allow Stop/Shutdown
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			case svc.Interrogate:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case <-time.After(delay):
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}

	if !registered {
		log.Fatalln("This computer is not registered on the server.")
	}

	utils.Info("Is computer registered: ", registered)
	var tokens auth.Tokens

	// load refresh token and refresh access token
	if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
		if nt, rerr := as.RefreshTokens(rt); rerr == nil {
			tokens = nt
			// uložit nový refresh token po rotaci
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				utils.Error("warning: failed to save refresh token after refresh:", err)
			}
		} else {
			utils.Error("token refresh failed, trying recover:", rerr)
			if nt, rerr2 := as.RecoverTokens(); rerr2 == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					utils.Error("warning: failed to save refresh token after recover:", err)
				}
			} else {
				utils.Error("token recover failed:", rerr2)
			}
		}
	} else {
		utils.Info("refresh token not found, attempting recover without refresh token")
		if nt, rerr := as.RecoverTokens(); rerr == nil {
			tokens = nt
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				utils.Error("warning: failed to save refresh token after recover:", err)
			}
		} else {
			utils.Error("token recover failed:", rerr)
		}
	}

	ms.Tokens = &tokens

	// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
	auth.InitHTTPClient(as, ms.Tokens, func(nt auth.Tokens) {
		if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
			utils.Error("error saving refresh token after refresh:", err)
		}
	})

	// Initialize auto-updater
	updater.InitUpdater(serverURL)

	go ms.StartRustDeskServerSync()
	go ms.StartRustDeskServerTasks()
	go ms.StartApplicationsManagement()

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
				utils.Errorf("Unknown service command: %d", c.Cmd)
			}
		case <-ticker.C:
			fmt.Println("Service heartbeat...")
		}
	}
}

type logWriter struct {
	path string
}

func configureInstallerCommandLogging(explicitPath string) (string, error) {
	logPath := strings.TrimSpace(explicitPath)
	if logPath == "" {
		logPath = filepath.Join(os.TempDir(), "FleetCtrlInstaller.log")
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create installer log directory: %w", err)
	}

	log.SetOutput(io.MultiWriter(os.Stderr, logWriter{path: logPath}))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("FleetCtrl installer command log: %s", logPath)

	return logPath, nil
}

func (w logWriter) Write(p []byte) (n int, err error) {
	// Check if rotation is needed
	if info, err := os.Stat(w.path); err == nil {
		if info.Size() > consts.MaxLogSize {
			oldPath := w.path + ".old"
			_ = os.Remove(oldPath)         // Ignore error if not exists
			_ = os.Rename(w.path, oldPath) // Ignore error if file is open elsewhere, just don't rotate this time
		}
	}

	// Try to open the file with a small retry logic for transient locks
	var f *os.File
	for i := 0; i < 3; i++ {
		f, err = os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		// If we still can't open it (e.g. hard lock), return len(p) to prevent pipe break
		return len(p), nil
	}
	defer f.Close()
	return f.Write(p)
}

func logInstallerExecutionContext(commandName string, serverURL string, isMSI bool) {
	exePath, exeErr := os.Executable()
	if exeErr != nil {
		exePath = fmt.Sprintf("<error: %v>", exeErr)
	}

	cwd, cwdErr := os.Getwd()
	if cwdErr != nil {
		cwd = fmt.Sprintf("<error: %v>", cwdErr)
	}

	username := "<unknown>"
	userSID := "<unknown>"
	if currentUser, err := user.Current(); err == nil {
		if strings.TrimSpace(currentUser.Username) != "" {
			username = currentUser.Username
		}
		if strings.TrimSpace(currentUser.Uid) != "" {
			userSID = currentUser.Uid
		}
	} else {
		username = fmt.Sprintf("<error: %v>", err)
		userSID = fmt.Sprintf("<error: %v>", err)
	}

	elevated := false
	if token := windows.GetCurrentProcessToken(); token != 0 {
		elevated = token.IsElevated()
	}

	proxyInfo := "<not checked>"
	trimmedServerURL := strings.TrimSpace(serverURL)
	if trimmedServerURL != "" {
		probeURL := strings.TrimRight(trimmedServerURL, "/") + "/health"
		if req, err := http.NewRequest(http.MethodGet, probeURL, nil); err == nil {
			if proxyURL, err := http.ProxyFromEnvironment(req); err != nil {
				proxyInfo = fmt.Sprintf("proxy lookup error: %v", err)
			} else if proxyURL != nil {
				proxyInfo = proxyURL.String()
			} else {
				proxyInfo = "DIRECT"
			}
		} else {
			proxyInfo = fmt.Sprintf("request build error: %v", err)
		}
	}

	log.Printf("Installer context: command=%s isMSI=%v exe=%s cwd=%s", commandName, isMSI, exePath, cwd)
	log.Printf("Installer context: user=%s sid=%s elevated=%v temp=%s", username, userSID, elevated, os.TempDir())
	log.Printf("Installer context: USERNAME=%q USERDOMAIN=%q TEMP=%q TMP=%q SYSTEMROOT=%q", os.Getenv("USERNAME"), os.Getenv("USERDOMAIN"), os.Getenv("TEMP"), os.Getenv("TMP"), os.Getenv("SystemRoot"))
	log.Printf("Installer context: serverURL=%q proxy=%s", trimmedServerURL, proxyInfo)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			installCmd := flag.NewFlagSet("install", flag.ExitOnError)
			enrollToken := installCmd.String("token", "", "Enrollment token")
			serverURL := installCmd.String("url", "", "Server URL")
			isMSI := installCmd.Bool("msi", false, "Installed via MSI")
			installerLog := installCmd.String("installer-log", "", "Installer log file path")

			err := installCmd.Parse(os.Args[2:])
			if err != nil {
				log.Fatal(err)
			}

			logPath, err := configureInstallerCommandLogging(*installerLog)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to initialize installer logging: %v\n", err)
				os.Exit(1)
			}

			logInstallerExecutionContext("install", *serverURL, *isMSI)

			if *enrollToken == "" || *serverURL == "" {
				log.Fatalf("missing --token or --url. See log: %s", logPath)
			}

			err = manager.InstallService(*enrollToken, *serverURL, *isMSI)
			if err != nil {
				log.Fatalf("install failed. Error: %v", err)
			}
			log.Printf("Install command completed successfully. Log: %s", logPath)
			return
		case "remove":
			removeCmd := flag.NewFlagSet("remove", flag.ExitOnError)
			installerLog := removeCmd.String("installer-log", "", "Installer log file path")
			deleteDeviceID := removeCmd.Bool("delete-device-id", false, "Delete the persisted DeviceID from registry")

			err := removeCmd.Parse(os.Args[2:])
			if err != nil {
				log.Fatal(err)
			}

			logPath, err := configureInstallerCommandLogging(*installerLog)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to initialize installer logging: %v\n", err)
				os.Exit(1)
			}

			logInstallerExecutionContext("remove", "", false)

			err = manager.RemoveService(!*deleteDeviceID)
			if err != nil {
				log.Fatalf("remove failed. See log: %s. Error: %v", logPath, err)
			}
			log.Printf("Remove command completed successfully. Log: %s", logPath)
			return
		case "update":
			updateCmd := flag.NewFlagSet("update", flag.ExitOnError)
			installerLog := updateCmd.String("installer-log", "", "Installer log file path")

			err := updateCmd.Parse(os.Args[2:])
			if err != nil {
				log.Fatal(err)
			}

			logPath, err := configureInstallerCommandLogging(*installerLog)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to initialize installer logging: %v\n", err)
				os.Exit(1)
			}

			logInstallerExecutionContext("update", "", false)

			err = manager.UpdateService()
			if err != nil {
				log.Fatalf("update failed. See log: %s. Error: %v", logPath, err)
			}
			log.Printf("Update command completed successfully. Log: %s", logPath)
			return
		}
	}

	// redirect logger output to a custom writer that opens/closes the file for each write
	logPath := filepath.Join(consts.TargetDir, "client.log")
	log.SetOutput(logWriter{path: logPath})

	// set format (date, time, file:line)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	utils.Infof("Starting fleetctrl-client version %s...", consts.Version)

	if !consts.Production {
		serverURL, err := registry.GetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
		if err != nil {
			log.Fatalln("error getting key from registry: ", err)
		}

		as := auth.NewAuthService(serverURL)
		ms := service.NewMainService(as, serverURL)
		deviceID, hasDeviceID, err := auth.LoadDeviceID()
		if err != nil {
			log.Fatalf("chyba při načítání DeviceID: %v", err)
		}
		if !hasDeviceID {
			log.Fatalln("DeviceID chybí. Proveďte nové enrollnutí nebo reinstall klienta.")
		}

		// check if computer is registered
		registered, err := as.IsEnrolled(deviceID)
		if err != nil {
			log.Fatalf("chyba při kontrole registrace: %v", err)
		}

		if !registered {
			log.Fatalln("This computer is not registered on the server.")
		}

		var tokens auth.Tokens

		if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
			if nt, rerr := as.RefreshTokens(rt); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					utils.Error("warning: failed to save refresh token after refresh:", err)
				}
			} else {
				utils.Error("token refresh failed, trying recover:", rerr)
				if nt, rerr2 := as.RecoverTokens(); rerr2 == nil {
					tokens = nt
					if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
						utils.Error("warning: failed to save refresh token after recover:", err)
					}
				} else {
					utils.Error("token recover failed:", rerr2)
				}
			}
		} else {
			utils.Info("refresh token not found, attempting recover without refresh token")
			if nt, rerr := as.RecoverTokens(); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("warning: failed to save refresh token after recover:", err)
				}
			} else {
				utils.Error("token recover failed:", rerr)
			}
		}
		ms.Tokens = &tokens

		// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
		if err := database.Init(); err != nil {
			utils.Errorf("Failed to initialize database: %v", err)
		}
		defer database.Close()

		auth.InitHTTPClient(as, ms.Tokens, func(nt auth.Tokens) {
			if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				utils.Error("error saving refresh token after refresh:", err)
			}
		})

		// Initialize auto-updater
		updater.InitUpdater(serverURL)

		go ms.StartRustDeskServerSync()
		go ms.StartRustDeskServerTasks()
		for {
			time.Sleep(1 * time.Hour)
		}
	}

	if err := svc.Run(consts.ServiceName, &serviceHandler{}); err != nil {
		log.Fatalf("service error: %v", err)
	}
}
