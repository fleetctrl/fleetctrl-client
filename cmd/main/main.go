package main

import (
	"KiskaLE/RustDesk-ID/cmd/internal/auth"
	consts "KiskaLE/RustDesk-ID/cmd/internal/const"
	"KiskaLE/RustDesk-ID/cmd/internal/utils"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
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

type MainService struct {
	as        *auth.AuthService
	serverUrl string
	tokens    *auth.Tokens
}

func NewMainService(serverUrl string, as *auth.AuthService) *MainService {
	return &MainService{serverUrl: serverUrl, as: as}
}

func (ms *MainService) startRustDeskServerSync() {
	fmt.Println("Starting RustDesk sync...")
	for {
		// check connection to server
		ping, err := utils.Ping(ms.serverUrl)
		if err != nil {
			log.Printf("chyba při kontrole připojení k serveru: %v", err)
			time.Sleep(15 * time.Minute)
			continue
		}
		if !ping {
			log.Println("Server není dostupný. Čekám 15 minut na další pokus...")
			time.Sleep(15 * time.Minute)
			continue
		}

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

		dpop, err := auth.CreateDPoP(consts.ServerUrl+"/computer/rustdesk-sync", ms.tokens.AccessToken)
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		res, err := utils.Patch(consts.ServerUrl+"/computer/rustdesk-sync", map[string]string{
			"name":            computer.Name,
			"rustdesk_id":     computer.RustdeskID,
			"ip":              computer.IP,
			"os":              computer.OS,
			"os_version":      computer.OSVersion,
			"login_user":      computer.LoginUser,
			"last_connection": computer.LastConnection,
		}, map[string]string{
			"Authorization": "Bearer " + ms.tokens.AccessToken,
			"Content-Type":  "application/json",
			"DPoP":          dpop,
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

		dpop, err := auth.CreateDPoP(consts.ServerUrl+"/tasks", ms.tokens.AccessToken)
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		// get tasks
		tasksRes, err := utils.Get(consts.ServerUrl+"/tasks", map[string]string{
			"Authorization": "Bearer " + ms.tokens.AccessToken,
			"Content-Type":  "application/json",
			"DPoP":          dpop,
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

		for i := 0; i < len(tasks); i++ {
			task := tasks[i]
			// set task started
			dpop, err = auth.CreateDPoP(consts.ServerUrl+"/task/"+task.ID, ms.tokens.AccessToken)
			if err != nil {
				log.Println(err)
				time.Sleep(15 * time.Minute)
				continue
			}
			utils.Patch(consts.ServerUrl+"/task/"+task.ID, map[string]string{
				"status": "IN_PROGRESS",
				"error":  "",
			}, map[string]string{
				"Authorization": "Bearer " + ms.tokens.AccessToken,
				"Content-Type":  "application/json",
				"DPoP":          dpop,
			})
			switch task.Task {
			case "SET_PASSWD":
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
					dpop, err = auth.CreateDPoP(consts.ServerUrl+"/task/"+task.ID, ms.tokens.AccessToken)
					if err != nil {
						log.Println(err)
						time.Sleep(15 * time.Minute)
						continue
					}
					utils.Patch(consts.ServerUrl+"/task/"+task.ID, map[string]string{
						"status": "ERROR",
						"error":  err.Error(),
					}, map[string]string{
						"Authorization": "Bearer " + ms.tokens.AccessToken,
						"Content-Type":  "application/json",
						"DPoP":          dpop,
					})
					break
				}
				log.Println("Password set")

				dpop, err = auth.CreateDPoP(consts.ServerUrl+"/task/"+task.ID, ms.tokens.AccessToken)
				if err != nil {
					log.Println(err)
					time.Sleep(15 * time.Minute)
					continue
				}

				utils.Patch(consts.ServerUrl+"/task/"+task.ID, map[string]string{
					"status": "SUCCESS",
					"error":  "",
				}, map[string]string{
					"Authorization": "Bearer " + ms.tokens.AccessToken,
					"Content-Type":  "application/json",
					"DPoP":          dpop,
				})

			}
		}

		time.Sleep(5 * time.Minute)
	}
}

func (s *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
	if err != nil {
		log.Fatalln("chyba při získávání klíča z registru: ", err)
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	// Označ službu jako běžící a přijímej Stop/Shutdown
	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

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
	// create folder
	err := os.MkdirAll(consts.TargetDir, 0755)
	if err != nil {
		log.Fatalf("chyba při vytváření adresáře: %v", err)
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

	// inicializovat registry
	err = CreateRegistryKey(registry.LOCAL_MACHINE, consts.CompanyRegitryKey)
	if err != nil {
		log.Fatalf("chyba při inicializování registry: %v", err)
	}
	err = CreateRegistryKey(registry.LOCAL_MACHINE, consts.RegisteryRootKey)
	if err != nil {
		log.Fatalf("chyba při inicializování registry: %v", err)
	}

	// vytvoření registeru s verzí clienta
	var versionKey = RegistryValue{Type: RegistryString, Value: consts.Version}
	key, err := SetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "version", versionKey)
	if err != nil {
		log.Fatalln("chyba při nastavování hodnoty v registru: ", err)
	}
	key.Close()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			serverUrl := os.Args[2]
			anonKey := os.Args[3]
			if serverUrl == "" || anonKey == "" {
				fmt.Println("Musi byt zadna server url a anon key")
				log.Fatalln("Musi byt zadna server url a anon key")
			}
			// write server url and anon key to registry
			var serverUrlKey = RegistryValue{Type: RegistryString, Value: serverUrl}
			key, err := SetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url", serverUrlKey)
			if err != nil {
				log.Fatalf("chyba při nastavování hodnoty v registru: %v", err)
			}
			key.Close()
			var anonKeyKey = RegistryValue{Type: RegistryString, Value: anonKey}
			key, err = SetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "anon_key", anonKeyKey)
			if err != nil {
				log.Fatalf("chyba při nastavování hodnoty v registru: %v", err)
			}
			key.Close()

			err = InstallService(consts.ServiceName, consts.ServiceDisplayName)
			if err != nil {
				log.Fatalf("chyba při instalaci služby: %v", err)
			}
			return
		case "remove":
			err := RemoveService(consts.ServiceName)
			if err != nil {
				log.Fatalf("chyba při odinstalování služby: %v", err)
			}
			return
		}
	}

	// check if computer is enrolled

	serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url")
	if err != nil {
		log.Fatalln("chyba při získávání klíča z registru: ", err)
	}

	as := auth.NewAuthService(serverURL)
	ms := NewMainService(serverURL, as)

	// check if computer is registered
	registered, err := ms.as.IsEnrolled()
	if err != nil {
		log.Fatalf("chyba při kontrole registrace: %v", err)
	}

	fmt.Println("Zda je počítač zaregistrován: ", registered)
	var tokens auth.Tokens
	if !registered {
		log.Println("Tento počítač není zaregistrován na serveru. Registruji...")
		tokens, err = ms.as.Enroll()
		if err != nil {
			log.Fatalf("chyba při registraci počítače: %v", err)
		}
		err = auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt")
		if err != nil {
			log.Fatalln("chyba při ukládání klíče: ", err)
			return
		}
	} else {
		// load refresh token
		refreshToken, err := auth.LoadRefreshToken(consts.ProgramDataDir+"/tokens", "refresh_token.txt")
		if err != nil {
			log.Fatalln("chyba při získávání klíče: ", err)
			return
		}
		// request new access token from server
		tokens, err = ms.as.RefreshTokens(refreshToken)
		if err != nil {
			log.Fatalf("chyba při aktualizování tokenu: %v", err)
			return
		}
		// save refresh token
		err = auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt")
		if err != nil {
			log.Fatalln("chyba při ukládání klíče: ", err)
			return
		}
	}
	ms.tokens = &tokens

	if !consts.Production {
		// initialize supabase client
		// for dev only

		//go ms.startRustDeskServerSync()
		go ms.startRustDeskServerTasks()
		for {
			time.Sleep(1 * time.Hour)
		}
	}

	go ms.startRustDeskServerSync()
	go ms.startRustDeskServerTasks()

	if err := svc.Run(consts.ServiceName, &serviceHandler{}); err != nil {
		log.Fatalf("chyba služby: %v", err)
	}
}
