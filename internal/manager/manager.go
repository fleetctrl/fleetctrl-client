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
	"strings"
	"time"

	winreg "golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func RemoveService(preserveDeviceID bool) error {
	// Nastavení verze na 0
	if err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "version", registry.RegistryValue{Type: registry.RegistryString, Value: "0"}); err != nil {
		log.Printf("Chyba při nastavení verze: %v", err)
	}

	if !preserveDeviceID {
		if err := registry.DeleteRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, consts.DeviceIDValueName); err != nil {
			log.Printf("Chyba při mazání DeviceID z registry: %v", err)
		}
	}

	// Check if installed via MSI
	if isMSI, err := registry.GetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "installed_via_msi"); err == nil && isMSI != "" {
		log.Printf("POZOR: Tato instance byla nainstalována pomocí MSI. Manuální odstranění služby sice funguje, ale MSI balíček může zůstat v systému jako 'nainstalovaný'.")
		log.Printf("Doporučujeme provést odinstalaci přes 'Přidat nebo odebrat programy'.")
	}

	m, err := mgr.Connect()
	if err != nil {
		log.Printf("Chyba při připojení ke správci služeb: %v", err)
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(consts.ServiceName)
	if err != nil {
		log.Printf("Služba %s neexistuje nebo nelze otevřít: %v", consts.ServiceName, err)
	} else {
		defer s.Close()

		// Nejdříve zastavit službu, pokud běží
		status, err := s.Query()
		if err == nil && status.State == svc.Running {
			log.Printf("Zastavuji běžící službu...")
			_, err = s.Control(svc.Stop)
			if err != nil {
				log.Printf("Varování při zastavování služby: %v", err)
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
			log.Printf("chyba při mazání služby: %v", err)
			return err
		}
		s.Close()
		log.Printf("Služba byla úspěšně smazána.")
	}

	time.Sleep(time.Duration(5) * time.Second)

	for i := 0; i < 3; i++ {
		err = cleanupProgramData(preserveDeviceID)
		if err == nil {
			break
		}
		log.Printf("Pokus %d/3 mazání dat selhal: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	// Odstranění dat s retry logikou
	for i := 0; i < 3; i++ {
		err = TakeOwnershipAndDelete(consts.TargetDir)
		if err == nil {
			break
		}
		log.Printf("Pokus %d/3 mazání složky selhal: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	return nil
}

func InstallService(enrollToken string, serverURL string, isMSI bool) error {
	serverURL = strings.TrimSpace(serverURL)
	serverURL = strings.TrimRight(serverURL, "/")
	if serverURL != "" && !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}
	enrollToken = strings.TrimSpace(enrollToken)

	// kontrola jestli je server dostupný
	for i := 0; i < 3; i++ {
		ping, err := utils.Ping(serverURL)
		if err == nil && ping {
			log.Printf("Server %s je dostupný.", serverURL)
			break
		}
		log.Printf("Navázání připojení k serveru selhalo. Pokus %d/3.", i+1)
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
		if err := RemoveService(true); err != nil {
			return err
		}
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
	if err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "version", versionKey); err != nil {
		return errors.New("chyba při nastavování hodnoty v registru: " + err.Error())
	}

	var serverURLKey = registry.RegistryValue{Type: registry.RegistryString, Value: serverURL}
	if err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "server_url", serverURLKey); err != nil {
		return errors.New("chyba při nastavování hodnoty server_url v registru: " + err.Error())
	}

	if isMSI {
		var msiKey = registry.RegistryValue{Type: registry.RegistryDword, Value: float64(1)}
		if err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "installed_via_msi", msiKey); err != nil {
			return errors.New("chyba při nastavování hodnoty installed_via_msi v registru: " + err.Error())
		}
	}

	as := auth.NewAuthService(serverURL)
	existingDeviceID, _, err := auth.LoadDeviceID()
	if err != nil {
		return errors.New("chyba při načítání DeviceID: " + err.Error())
	}
	privKeyPath := filepath.Join(consts.ProgramDataDir, "certs", "priv.jwk")
	privKeyInfo, statErr := os.Stat(privKeyPath)
	privKeyExist := statErr == nil && !privKeyInfo.IsDir()

	// pokus o obnovu připojení
	recoverFailed := false
	if existingDeviceID != "" && privKeyExist {
		isEnrolled, err := as.IsEnrolled(existingDeviceID)
		if err != nil {
			utils.Error("chyba při kontrole registrace zařízení:", err)
			recoverFailed = true
		} else if !isEnrolled {
			utils.Info("zařízení není zaregistrováno na serveru, bude provedena nová registrace")
			recoverFailed = true
		} else {
			if nt, rerr := as.RecoverTokens(); rerr == nil {
				tokens := nt
				if err := auth.SaveRefershToken(tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
					utils.Error("warning: failed to save refresh token after recover:", err)
					recoverFailed = true
				}
			} else {
				utils.Error("token recover failed:", rerr)
				recoverFailed = true
			}
		}
	}

	// Pokud obnova selže nebo zařízení není zaregistrováno, tak zaregistrovat znovu
	if recoverFailed || existingDeviceID == "" || !privKeyExist {
		enrollment, err := as.Enroll(enrollToken)
		if err != nil {
			return errors.New("chyba při registraci počítače: " + err.Error())
		}
		if enrollment.DeviceID == "" {
			return errors.New("server nevrátil device ID")
		}
		if err := auth.SaveDeviceID(enrollment.DeviceID); err != nil {
			return errors.New("chyba při ukládání DeviceID: " + err.Error())
		}
		if err := auth.SaveRefershToken(enrollment.Tokens.RefreshToken, consts.ProgramDataDir+"/tokens", "refresh_token.txt"); err != nil {
			return errors.New("chyba při ukládání klíče: " + err.Error())
		}
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

	log.Printf("Služba %s byla úspěšně vytvořena", consts.ServiceName)

	// Spuštění služby s retry logikou
	for i := 0; i < 3; i++ {
		err = s.Start()
		if err == nil {
			log.Printf("Služba %s byla úspěšně spuštěna", consts.ServiceName)
			break
		}
		log.Printf("Pokus %d/3 spuštění služby selhal: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
		if i == 2 {
			return err
		}
	}

	return nil
}

func TakeOwnershipAndDelete(path string) error {
	// zjistit jestli adresář existuje
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
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
	removeArgs := []string{"/C", "del", "/F", "/Q", path}
	if info.IsDir() {
		removeArgs = []string{"/C", "rd", "/S", "/Q", path}
	}
	cmdRemove := exec.Command("cmd", removeArgs...)
	out, err = cmdRemove.CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove error: %v, output: %s", err, out)
	}

	return nil
}

func cleanupProgramData(preserveDeviceID bool) error {
	if !preserveDeviceID {
		return TakeOwnershipAndDelete(consts.ProgramDataDir)
	}

	entries, err := os.ReadDir(consts.ProgramDataDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.Name() == "certs" {
			continue
		}
		if err := TakeOwnershipAndDelete(filepath.Join(consts.ProgramDataDir, entry.Name())); err != nil {
			return err
		}
	}

	return nil
}

func UpdateService() error {
	log.Printf("Zahajuji aktualizaci služby...")

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
		log.Printf("Zastavuji běžící službu...")
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
		log.Printf("Služba byla zastavena.")
	}

	// Krátká pauza pro uvolnění souborů
	time.Sleep(2 * time.Second)

	// Zkopírovat nový executable
	if err := CopyExecutable(); err != nil {
		return fmt.Errorf("chyba při kopírování souboru: %v", err)
	}

	// Aktualizovat verzi v registru
	var versionKey = registry.RegistryValue{Type: registry.RegistryString, Value: consts.Version}
	if err := registry.SetRegisteryValue(winreg.LOCAL_MACHINE, consts.RegisteryRootKey, "version", versionKey); err != nil {
		log.Printf("Varování: chyba při aktualizaci verze v registru: %v", err)
	}

	// Spustit službu znovu
	log.Printf("Spouštím službu...")
	for i := 0; i < 3; i++ {
		err = s.Start()
		if err == nil {
			log.Printf("Služba %s byla úspěšně aktualizována a spuštěna.", consts.ServiceName)
			log.Printf("Nová verze: %s", consts.Version)
			return nil
		}
		log.Printf("Pokus %d/3 spuštění služby selhal: %v", i+1, err)
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

	// Pokud source == target (např. MSI již soubor nainstaloval), přeskočit kopírování
	targetPath := filepath.Join(consts.TargetDir, consts.TargetExeName)
	if filepath.Clean(sourcePath) == filepath.Clean(targetPath) {
		log.Printf("Soubor je již na cílovém místě (%s), přeskakuji kopírování.", sourcePath)
		return nil
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
	targetPath = filepath.Join(consts.TargetDir, consts.TargetExeName)

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
