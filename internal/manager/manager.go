package manager

import (
	"KiskaLE/RustDesk-ID/internal/auth"
	consts "KiskaLE/RustDesk-ID/internal/const"
	"KiskaLE/RustDesk-ID/internal/registry"
	"KiskaLE/RustDesk-ID/internal/utils"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	winreg "golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func RemoveService() error {
	// Nastavení verze na 0
	key, err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "version", registry.RegistryValue{Type: registry.RegistryString, Value: "0"})
	if err != nil {
		fmt.Println("Chyba při nastavení verze: ", err)
	}

	if key != winreg.Key(0) {
		key.Close()
	}

	m, err := mgr.Connect()
	if err != nil {
		fmt.Printf("Chyba při připojení ke správci služeb: %v", err)
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(consts.ServiceName)
	if err != nil {
		fmt.Printf("Služba %s neexistuje nebo nelze otevřít: %v", consts.ServiceName, err)
	} else {
		defer s.Close()

		// Nejdříve zastavit službu, pokud běží
		status, err := s.Query()
		if err == nil && status.State == svc.Running {
			fmt.Println("Zastavuji běžící službu...")
			_, err = s.Control(svc.Stop)
			if err != nil {
				fmt.Printf("Varování při zastavování služby: %v", err)
			} else {
				// Počkat na zastavení služby
				for i := 0; i < 30; i++ {
					time.Sleep(1 * time.Second)
					status, err := s.Query()
					if err != nil || status.State == svc.Stopped {
						break
					}
				}
			}
		}

		// Nyní smazat službu
		err = s.Delete()
		if err != nil {
			fmt.Println("chyba při mazání služby: ", err)
			return err
		}
		s.Close()
		fmt.Println("Služba byla úspěšně smazána.")
	}

	time.Sleep(time.Duration(5) * time.Second)

	for i := 0; i < 3; i++ {
		err = TakeOwnershipAndDelete(consts.ProgramDataDir)
		if err == nil {
			break
		}
		fmt.Printf("Pokus %d/3 mazání složky selhal: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	// Odstranění dat s retry logikou
	for i := 0; i < 3; i++ {
		err = TakeOwnershipAndDelete(consts.TargetDir)
		if err == nil {
			break
		}
		fmt.Printf("Pokus %d/3 mazání složky selhal: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return nil
}

func InstallService(enrollToken string, serverURL string) error {
	// kontrola jestli je server dostupný
	for i := 0; i < 3; i++ {
		ping, err := utils.Ping(serverURL)
		if err == nil && ping {
			fmt.Printf("Server %s je dostupný.\n", serverURL)
			break
		}
		fmt.Printf("Navázání připojení k serveru selhalo. Pokus %d/3.\n", i+1)
		time.Sleep(time.Duration(i+1) * time.Second)
		if i == 2 {
			return errors.New("Navazání připojení k serveru selhalo.")
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	exePath := filepath.Join(consts.TargetDir, consts.TargetExeName)
	// zjistit jestli služba není zaregistrována
	s, err := m.OpenService(consts.ServiceName)
	if err == nil {
		// Služba existuje
		s.Close()
		// Spuštění odstranění služby
		RemoveService()
	}

	// create folder
	err = os.MkdirAll(consts.TargetDir, 0755)
	if err != nil {
		return errors.New("chyba při vytváření adresáře: " + err.Error())
	}

	// inicializovat registry
	err = registry.CreateRegistryKey(winreg.LOCAL_MACHINE, consts.CompanyRegitryKey)
	if err != nil {
		return errors.New("chyba při inicializování registry: " + err.Error())
	}
	err = registry.CreateRegistryKey(winreg.LOCAL_MACHINE, consts.RegisteryRootKey)
	if err != nil {
		return errors.New("chyba při inicializování registry: " + err.Error())
	}

	// vytvoření registru s verzí klienta
	var versionKey = registry.RegistryValue{Type: registry.RegistryString, Value: consts.Version}
	key, err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "version", versionKey)
	if err != nil {
		return errors.New("chyba při nastavování hodnoty v registru: " + err.Error())
	}
	key.Close()

	var serverURLKey = RegistryValue{Type: RegistryString, Value: serverURL}
	key, err = SetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url", serverURLKey)
	if err != nil {
		return errors.New("chyba při nastavování hodnoty server_url v registru: " + err.Error())
	}
	key.Close()

	as := auth.NewAuthService(serverURL)
	tokens, err := as.Enroll(enrollToken)
	if err != nil {
		return errors.New("chyba při registraci počítače: " + err.Error())
	}
	if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
		return errors.New("chyba při ukládání klíče: " + err.Error())
	}

	// Kopírování souboru
	if err := CopyExecutable(); err != nil {
		return err
	}

	// Vytvoření služby a získání handleru
	s, err = m.CreateService(
		consts.ServiceName,
		exePath,
		mgr.Config{
			DisplayName:      consts.ServiceDisplayName,
			StartType:        mgr.StartAutomatic,
			ServiceStartName: "LocalSystem",
		},
	)

	if err != nil {
		return errors.New("chyba při vytváření handleru služby:" + err.Error())
	}

	defer s.Close()

	fmt.Printf("Služba %s byla úspěšně vytvořena", consts.ServiceName)

	// Spuštění služby s retry logikou
	for i := 0; i < 3; i++ {
		err = s.Start()
		if err == nil {
			fmt.Printf("Služba %s byla úspěšně spuštěna", consts.ServiceName)
			break
		}
		fmt.Printf("Pokus %d/3 spuštění služby selhal: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
		if i == 2 {
			return err
		}
	}

	return nil
}

func TakeOwnershipAndDelete(path string) error {
	// zjistit jestli adresář existuje
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	// 1. Převzít vlastnictví
	cmdTakeown := exec.Command("takeown", "/F", path, "/R", "/D", "Y")
	out, err := cmdTakeown.CombinedOutput()
	if err != nil {
		return fmt.Errorf("takeown error: %v, output: %s", err, out)
	}

	// 2. Nastavit plná práva pro administrátory
	cmdIcacls := exec.Command("icacls", path, "/grant", "Administrators:F", "/T")
	out, err = cmdIcacls.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls error: %v, output: %s", err, out)
	}

	// 3. Smazat adresář/soubor
	cmdRemove := exec.Command("cmd", "/C", "rd", "/S", "/Q", path)
	out, err = cmdRemove.CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove error: %v, output: %s", err, out)
	}

	return nil
}

func UpdateService() error {
	fmt.Println("Zahajuji aktualizaci služby...")

	// Připojení ke správci služeb
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("chyba při připojení ke správci služeb: %v", err)
	}
	defer m.Disconnect()

	// Otevření služby
	s, err := m.OpenService(consts.ServiceName)
	if err != nil {
		return fmt.Errorf("služba %s neexistuje: %v", consts.ServiceName, err)
	}
	defer s.Close()

	// Zastavit službu pokud běží
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("chyba při dotazování na stav služby: %v", err)
	}

	if status.State == svc.Running {
		fmt.Println("Zastavuji běžící službu...")
		_, err = s.Control(svc.Stop)
		if err != nil {
			return fmt.Errorf("chyba při zastavování služby: %v", err)
		}

		// Počkat na zastavení služby
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
			status, err := s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
		fmt.Println("Služba byla zastavena.")
	}

	// Krátká pauza pro uvolnění souborů
	time.Sleep(2 * time.Second)

	// Zkopírovat nový executable
	if err := CopyExecutable(); err != nil {
		return fmt.Errorf("chyba při kopírování souboru: %v", err)
	}

	// Aktualizovat verzi v registru
	var versionKey = registry.RegistryValue{Type: registry.RegistryString, Value: consts.Version}
	key, err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "version", versionKey)
	if err != nil {
		fmt.Printf("Varování: chyba při aktualizaci verze v registru: %v\n", err)
	} else {
		key.Close()
	}

	// Spustit službu znovu
	fmt.Println("Spouštím službu...")
	for i := 0; i < 3; i++ {
		err = s.Start()
		if err == nil {
			fmt.Printf("Služba %s byla úspěšně aktualizována a spuštěna.\n", consts.ServiceName)
			fmt.Printf("Nová verze: %s\n", consts.Version)
			return nil
		}
		fmt.Printf("Pokus %d/3 spuštění služby selhal: %v\n", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	return fmt.Errorf("službu se nepodařilo spustit po aktualizaci: %v", err)
}

func CopyExecutable() error {
	// Získat cestu k aktuálnímu spustitelnému souboru
	sourcePath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return fmt.Errorf("chyba při získávání cesty k souboru: %v", err)
	}

	// pokud cílový adresář existuje, tak smazat
	if _, err := os.Stat(consts.TargetDir); err == nil {
		if err := os.RemoveAll(consts.TargetDir); err != nil {
			return fmt.Errorf("chyba při smazání adresáře: %v", err)
		}
	}

	// Vytvořit cílový adresář
	if err := os.MkdirAll(consts.TargetDir, 0755); err != nil {
		return fmt.Errorf("chyba při vytváření adresáře: %v", err)
	}

	// Sestavit cílovou cestu
	targetPath := filepath.Join(consts.TargetDir, consts.TargetExeName)

	// Zkopírovat soubor
	input, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("chyba při čtení zdrojového souboru: %v", err)
	}

	if err := os.WriteFile(targetPath, input, 0755); err != nil {
		return fmt.Errorf("chyba při zápisu cílového souboru: %v", err)
	}

	log.Printf("Soubor úspěšně zkopírován do: %s", targetPath)
	return nil
}
