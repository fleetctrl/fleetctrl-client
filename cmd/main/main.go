package main

import (
	"KiskaLE/RustDesk-ID/internal/auth"
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/manager"
	"KiskaLE/RustDesk-ID/internal/registry"
	"KiskaLE/RustDesk-ID/internal/service"
	"KiskaLE/RustDesk-ID/internal/updater"
	"KiskaLE/RustDesk-ID/internal/utils"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

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
	as := auth.NewAuthService(serverURL)
	ms := service.NewMainService(as, serverURL)

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
			registered, err = as.IsEnrolled()
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

			err = manager.InstallService(*enrollToken, *serverURL)
			if err != nil {
				panic(err)
			}
			return
		case "remove":
			err := manager.RemoveService()
			if err != nil {
				panic(err)
			}
			return
		case "update":
			err := manager.UpdateService()
			if err != nil {
				panic(err)
			}
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

		// check if computer is registered
		registered, err := as.IsEnrolled()
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
