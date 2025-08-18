package main

import (
	"KiskaLE/RustDesk-ID/utils"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
	"github.com/supabase-community/supabase-go"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

const (
	version            = "0.2.1"
	production         = true
	serviceName        = "fleetctrl-client"
	serviceDisplayName = "fleetctrl client"
	targetDir          = `C:\Program Files\fleetctrl`
	targetExeName      = "client.exe"
	companyRegitryKey  = `SOFTWARE\WOW6432Node\fleetctrl`
	registeryRootKey   = `SOFTWARE\WOW6432Node\fleetctrl\client`
)

type serviceHandler struct{}

type Task struct {
	UUID      string          `json:"uuid"`
	CreatedAt time.Time       `json:"created_at"`
	Status    string          `json:"status"`
	Task      string          `json:"task"`
	TaskData  json.RawMessage `json:"task_data"`
}

type SetPasswordTask struct {
	Password string `json:"password"`
}

type MainService struct {
	client    *supabase.Client
	serverUrl string
}

func NewMainService(client *supabase.Client, serverUrl string) *MainService {
	return &MainService{client: client, serverUrl: serverUrl}
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
		registered, err := ms.isRegistered()
		if err != nil {
			panic(fmt.Sprintf("chyba při kontrole registrace: %v", err))
		}
		if !registered {
			log.Println("Tento počítač není zaregistrován na serveru. Registruji...")
			err := ms.registerComputer()
			if err != nil {
				log.Println("chyba při registraci počítače: ", err)
			}
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

		key, err := GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key")
		if err != nil {
			log.Println("Neexistuje key pro autentikaci pc")
			time.Sleep(15 * time.Minute)
			continue
		}

		type Computer struct {
			Name           string `json:"in_name"`
			RustdeskID     string `json:"in_rustdesk_id"`
			ComputerKey    string `json:"in_key"`
			IP             string `json:"in_ip"`
			OS             string `json:"in_os"`
			OSVersion      string `json:"in_os_version"`
			LoginUser      string `json:"in_login_user"`
			LastConnection string `json:"in_last_connection"`
		}

		computer := Computer{
			Name:           computerName,
			RustdeskID:     rustdeskID,
			ComputerKey:    key,
			IP:             computerIP,
			OS:             os,
			OSVersion:      osVersion,
			LoginUser:      loginUser,
			LastConnection: time.Now().Format(time.RFC3339),
		}

		update := ms.client.Rpc("update_computer", "", computer)
		if update != "true" {
			log.Printf("chyba při aktualizování počítače na serveru: %v", update)
			time.Sleep(15 * time.Minute)
			continue
		}

		time.Sleep(5 * time.Minute)
	}
}

func (ms *MainService) startRustDeskServerTasks() {
	log.Println("Starting tasks...")
	for {
		ping, err := utils.Ping(ms.serverUrl)
		if err != nil {
			log.Printf("error pinging server: %v", err)
		}
		if !ping {
			log.Println("Server is not reachable. Waiting 15 minutes...")
			time.Sleep(15 * time.Minute)
			continue
		}

		rustdeskID, err := utils.GetRustDeskID()
		if err != nil {
			log.Println(err)
			time.Sleep(15 * time.Minute)
			continue
		}

		key, err := GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key")
		if err != nil {
			log.Println("Neexistuje key pro autentikaci pc")
			time.Sleep(15 * time.Minute)
			continue
		}

		// get task from supabase
		tasksData := ms.client.Rpc("get_tasks_by_rustdesk_id", "", map[string]any{
			"in_rustdesk_id": rustdeskID,
			"in_key":         key,
		})
		var tasks []Task
		if err := json.Unmarshal([]byte(tasksData), &tasks); err != nil {
			log.Println(err)
		}

		for i := 0; i < len(tasks); i++ {
			task := tasks[i]
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
					ms.client.Rpc("set_task_error", "", map[string]any{
						"in_uuid":  task.UUID,
						"in_error": err.Error(),
					})
					break
				}
				log.Println("Password set")

				ms.client.Rpc("edit_task_status", "", map[string]any{
					"in_uuid":       task.UUID,
					"in_new_status": "SUCCESS",
				})

			}
		}

		time.Sleep(5 * time.Minute)
	}
}

func (ms *MainService) registerComputer() error {
	// check if registery key exists
	key, err := GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key")

	if err != nil || key == "" {
		// create registery key
		_, err = CreateRegistryKey(registry.LOCAL_MACHINE, companyRegitryKey)
		if err != nil {
			return fmt.Errorf("chyba při vytváření klíče v registru: %v", err)
		}
		_, err = CreateRegistryKey(registry.LOCAL_MACHINE, registeryRootKey)
		if err != nil {
			return fmt.Errorf("chyba při vytváření klíče v registru: %v", err)
		}
		newKey := uuid.New().String()
		var value = RegistryValue{Type: RegistryString, Value: newKey}
		key, err := SetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key", value)
		if err != nil {
			return fmt.Errorf("chyba při nastavování hodnoty v registru: %v", err)
		}
		key.Close()
	}

	key, err = GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key")
	if err != nil {
		return fmt.Errorf("chyba při získávání klíče z registru: %v", err)
	}

	// get rustdesk ID
	rustdeskID, err := utils.GetRustDeskID()
	if err != nil {
		return err
	}
	// get PC name
	computerName, err := utils.GetComputerName()
	if err != nil {
		return err
	}

	// check connection to server
	ping, err := utils.Ping(ms.serverUrl)
	if err != nil {
		log.Printf("chyba při kontrole připojení k serveru: %v", err)
		return err
	}
	for !ping {
		log.Println("Server není dostupný. Čekám 15 minut na další pokus...")
		time.Sleep(15 * time.Minute)
		ping, err = utils.Ping(ms.serverUrl)
		if err != nil {
			log.Printf("chyba při kontrole připojení k serveru: %v", err)
			return err
		}
	}

	type Computer struct {
		Name        string `json:"in_name"`
		RustdeskID  string `json:"in_rustdesk_id"`
		ComputerKey string `json:"in_key"`
	}

	computer := Computer{
		Name:        computerName,
		RustdeskID:  rustdeskID,
		ComputerKey: key,
	}

	res := ms.client.Rpc("register_computer", "", computer)

	if res != "true" {
		return fmt.Errorf("chyba při registraci počítače: %v", res)
	}

	return nil
}

func (s *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	anonKey, err := GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "anon_key")
	if err != nil {
		log.Fatalln("chyba při získávání klíča z registru: ", err)
	}

	serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "server_url")
	if err != nil {
		log.Fatalln("chyba při získávání klíča z registru: ", err)
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}

	// initialize supabase client
	client, err := supabase.NewClient(serverURL, anonKey, &supabase.ClientOptions{})
	if err != nil {
		fmt.Println("cannot initalize client", err)
	}
	ms := NewMainService(client, serverURL)

	// check if computer is registered
	if client != nil {
		registered, err := ms.isRegistered()
		if err != nil {
			log.Printf("Error checking if computer is registered: %v", err)
		} else if !registered {
			log.Println("Registering computer...")
			if err := ms.registerComputer(); err != nil {
				log.Printf("Error registering computer: %v", err)
			}
		}
	}

	go ms.startRustDeskServerSync()

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

func (ms *MainService) isRegistered() (bool, error) {
	id, err := utils.GetRustDeskID()
	if err != nil {
		return false, err
	}

	active, err := utils.Ping(ms.serverUrl)
	if err != nil {
		return false, err
	}

	// wait until server is active
	for !active {
		time.Sleep(15 * time.Minute)
		active, err = utils.Ping(ms.serverUrl)
		if err != nil {
			return false, err
		}
	}

	isRegistered := ms.client.Rpc("is_computer_registered", "", map[string]interface{}{
		"in_rustdesk_id": id,
	})
	fmt.Println(isRegistered)
	if isRegistered != "false" {
		return true, nil
	}

	return false, nil
}

func main() {

	// create folder
	err := os.MkdirAll(targetDir, 0755)
	if err != nil {
		log.Fatalf("chyba při vytváření adresáře: %v", err)
	}
	// 1) otevřeme (nebo vytvoříme) soubor pro zápis
	f, err := os.OpenFile(targetDir+`\client.log`,
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
	_, err = CreateRegistryKey(registry.LOCAL_MACHINE, companyRegitryKey)
	if err != nil {
		log.Fatalf("chyba při inicializování registry: %v", err)
	}
	_, err = CreateRegistryKey(registry.LOCAL_MACHINE, registeryRootKey)
	if err != nil {
		log.Fatalf("chyba při inicializování registry: %v", err)
	}

	// vytvoř key pokud neexistuje
	_, err = GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key")
	if err != nil {
		// create key
		newKey := uuid.New().String()
		var value = RegistryValue{Type: RegistryString, Value: newKey}
		key, err := SetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key", value)
		if err != nil {
			log.Fatalf("chyba při nastavování hodnoty v registru: %v", err)
		}
		key.Close()
		_, err = GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "key")
		if err != nil {
			log.Fatalf("chyba při získávání klíče z registru: %v", err)
		}
	}

	// vytvoření registeru s verzí clienta
	var versionKey = RegistryValue{Type: RegistryString, Value: version}
	key, err := SetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "version", versionKey)
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
			key, err := SetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "server_url", serverUrlKey)
			if err != nil {
				log.Fatalf("chyba při nastavování hodnoty v registru: %v", err)
			}
			key.Close()
			var anonKeyKey = RegistryValue{Type: RegistryString, Value: anonKey}
			key, err = SetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "anon_key", anonKeyKey)
			if err != nil {
				log.Fatalf("chyba při nastavování hodnoty v registru: %v", err)
			}
			key.Close()

			err = InstallService(serviceName, serviceDisplayName)
			if err != nil {
				log.Fatalf("chyba při instalaci služby: %v", err)
			}
			return
		case "remove":
			err := RemoveService(serviceName)
			if err != nil {
				log.Fatalf("chyba při odinstalování služby: %v", err)
			}
			return
		}
	}

	anonKey, err := GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "anon_key")
	if err != nil {
		log.Fatalf("chyba při získávání klíče z registru: %v", err)
	}
	if !production {
		// initialize supabase client
		// for dev only
		serverURL, err := GetRegisteryValue(registry.LOCAL_MACHINE, registeryRootKey, "server_url")
		if err != nil {
			log.Fatalln("chyba při získávání klíča z registru: ", err)
		}

		client, err := supabase.NewClient(serverURL, anonKey, &supabase.ClientOptions{})
		if err != nil {
			fmt.Println("cannot initalize client", err)
		}
		ms := NewMainService(client, serverURL)
		// check if computer is registered
		registered, err := ms.isRegistered()
		if err != nil {
			log.Fatalf("chyba při kontrole registrace: %v", err)
		}
		fmt.Println("Zda je počítač zaregistrován: ", registered)
		if !registered {
			log.Println("Tento počítač není zaregistrován na serveru. Registruji...")
			err := ms.registerComputer()
			if err != nil {
				log.Fatalf("chyba při registraci počítače: %v", err)
			}
		}

		if err != nil {
			log.Fatalf("chyba při registraci počítače: %v", err)
		}

		go ms.startRustDeskServerSync()
		ms.startRustDeskServerTasks()
		for {
			time.Sleep(1 * time.Hour)
		}
	}

	if err := svc.Run(serviceName, &serviceHandler{}); err != nil {
		log.Fatalf("chyba služby: %v", err)
	}
}
