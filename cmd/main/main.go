package main

import (
	"KiskaLE/RustDesk-ID/cmd/internal/auth"
	consts "KiskaLE/RustDesk-ID/cmd/internal/const"
	"KiskaLE/RustDesk-ID/cmd/internal/utils"
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
				cmd := exec.Command("powershell", "-Command", "& 'C:\\Program Files\\RustDesk\\RustDesk.exe' --password "+d.Password)
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
				cmd := exec.Command("powershell", "-Command", "& 'C:\\Program Files\\RustDesk\\RustDesk.exe' --config "+cleanString)
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

func (s *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	// Označ službu jako běžící a přijímej Stop/Shutdown
	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
	if err != nil {
		log.Fatalln("chyba při získávání klíča z registru: ", err)
	}

	for {
		ok, err := utils.Ping(serverURL)
		if err == nil && ok {
			break
		}

		// čekej krátce, ale dovol Stop/Shutdown
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			case svc.Interrogate:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			}
		case <-time.After(5 * time.Second): // místo 5 minut; klidně exponenciální backoff
		}
	}

	// check if computer is enrolled

	as := auth.NewAuthService(serverURL)
	ms := NewMainService(as, serverURL)

	// check if computer is registered
	registered, err := ms.as.IsEnrolled()
	if err != nil {
		log.Fatalf("chyba při kontrole registrace: %v", err)
	}
	if !registered {
		log.Fatalln("Tento počítač není zaregistrován na serveru.")
	}

	fmt.Println("Zda je počítač zaregistrován: ", registered)
	var tokens auth.Tokens

	// načti refresh token a obnov access token
	if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
		if nt, rerr := ms.as.RefreshTokens(rt); rerr == nil {
			tokens = nt
			// uložit nový refresh token po rotaci
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("varování: nepodařilo se uložit refresh token po obnově:", err)
			}
		} else {
			log.Println("obnova tokenu z refresh selhala, zkusím recover:", rerr)
			if nt, rerr2 := ms.as.RecoverTokens(); rerr2 == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("varování: nepodařilo se uložit refresh token po recover:", err)
				}
			} else {
				log.Println("recover tokenů selhal:", rerr2)
			}
		}
	} else {
		log.Println("refresh token nebyl nalezen, pokusím se o recover bez refresh tokenu")
		if nt, rerr := ms.as.RecoverTokens(); rerr == nil {
			tokens = nt
			if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("varování: nepodařilo se uložit refresh token po recover:", err)
			}
		} else {
			log.Println("recover tokenů selhal:", rerr)
		}
	}

	ms.tokens = &tokens

	// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
	auth.InitHTTPClient(ms.as, ms.tokens, func(nt auth.Tokens) {
		if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
			log.Println("chyba při ukládání refresh tokenu po obnově:", err)
		}
	})

	go ms.startRustDeskServerSync()
	go ms.startRustDeskServerTasks()

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// Windows shell si někdy vyžádá stav
				changes <- svc.Status{
					State:   svc.Running,
					Accepts: svc.AcceptStop | svc.AcceptShutdown,
				}
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				return false, 0
			default:
				// ignoruj ostatní příkazy
				log.Printf("Neznámý příkaz služby: %d", c.Cmd)
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
				log.Fatalln("chybí --token nebo --url")
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
		}
	}

	// 1) otevřeme (nebo vytvoříme) soubor pro zápis
	f, err := os.OpenFile(consts.TargetDir+`\client.log`,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, // přidáváme na konec
		0o644)                               // práva rw-r-r
	if err != nil {
		log.Fatalf("nešlo otevřít log: %v", err)
	}
	defer f.Close()

	// 2) přesměrujeme výstup loggeru
	log.SetOutput(f)

	// 3) nastavíme formát (datum, čas, soubor:řádek)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if !consts.Production {
		// initialize supabase client
		// for dev only
		// check if computer is enrolled

		serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
		if err != nil {
			log.Fatalln("chyba při získávání klíča z registru: ", err)
		}

		as := auth.NewAuthService(serverURL)
		ms := NewMainService(as, serverURL)

		// check if computer is registered
		registered, err := ms.as.IsEnrolled()
		if err != nil {
			log.Fatalf("chyba při kontrole registrace: %v", err)
		}

		if !registered {
			log.Fatalln("Tento počítač není zaregistrován na serveru.")
		}

		var tokens auth.Tokens

		if rt, lerr := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt"); lerr == nil && rt != "" {
			if nt, rerr := ms.as.RefreshTokens(rt); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("varování: nepodařilo se uložit refresh token po obnově:", err)
				}
			} else {
				log.Println("obnova tokenu z refresh selhala, zkusím recover:", rerr)
				if nt, rerr2 := ms.as.RecoverTokens(); rerr2 == nil {
					tokens = nt
					if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
						log.Println("varování: nepodařilo se uložit refresh token po recover:", err)
					}
				} else {
					log.Println("recover tokenů selhal:", rerr2)
				}
			}
		} else {
			log.Println("refresh token nebyl nalezen, pokusím se o recover bez refresh tokenu")
			if nt, rerr := ms.as.RecoverTokens(); rerr == nil {
				tokens = nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					log.Println("varování: nepodařilo se uložit refresh token po recover:", err)
				}
			} else {
				log.Println("recover tokenů selhal:", rerr)
			}
		}
		ms.tokens = &tokens

		// Initialize HTTP client with auth middleware (Bearer + DPoP with auto-refresh)
		auth.InitHTTPClient(ms.as, ms.tokens, func(nt auth.Tokens) {
			if err := auth.SaveRefershToken(nt.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
				log.Println("chyba při ukládání refresh tokenu po obnově:", err)
			}
		})

		go ms.startRustDeskServerSync()
		go ms.startRustDeskServerTasks()
		for {
			time.Sleep(1 * time.Hour)
		}
	}

	if err := svc.Run(consts.ServiceName, &serviceHandler{}); err != nil {
		log.Fatalf("chyba služby: %v", err)
	}
}
