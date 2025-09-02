package main

import (
	consts "KiskaLE/RustDesk-ID/cmd/internal/const"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func RemoveService(serviceName string) error {
	// Nastavení verzne na 0
	key, err := SetRegisteryValue(registry.LOCAL_MACHINE, consts.RegisteryRootKey, "version", RegistryValue{Type: RegistryString, Value: "0"})
	if err != nil {
		log.Println("Chyba při nastavení verze: ", err)
	}

	if key != registry.Key(0) {
		key.Close()
	}

	m, err := mgr.Connect()
	if err != nil {
		log.Printf("Chyba při připojení ke správci služeb: %v", err)
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		log.Printf("Služba %s neexistuje nebo nelze otevřít: %v", serviceName, err)
	} else {
		defer s.Close()

		// Nejdříve zastavit službu, pokud běží
		status, err := s.Query()
		if err == nil && status.State == svc.Running {
			log.Println("Zastavuji běžící službu...")
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
			fmt.Println(err)
			log.Println("chyba při mazání služby: ", err)
			return err
		}
		s.Close()
		log.Println("Služba byla úspěšně smazána.")
	}

	time.Sleep(time.Duration(5) * time.Second)

	// Odstranění dat s retry logikou
	for i := 0; i < 3; i++ {
		err = TakeOwnershipAndDelete(consts.TargetDir)
		if err == nil {
			break
		}
		log.Printf("Pokus %d/3 mazání složky selhal: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	log.Println("Služba byla úspěšně odstraněna.")
	return nil
}

func TakeOwnershipAndDelete(path string) error {
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

func InstallService(serviceName string, serviceDisplayName string) error {
	// Kopírování souboru
	if err := copyExecutable(); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	exePath := filepath.Join(consts.TargetDir, consts.TargetExeName)

	// zjistit jesli služba není zaregistrována
	s, err := m.OpenService(serviceName)
	if err == nil {
		// Služba existuje
		s.Close()
		log.Printf("Služba %s existuje, spouštím ji", serviceName)

		time.Sleep(5 * time.Second)

		// Pokusit se spustit existující službu
		existingService, err := m.OpenService(serviceName)
		if err == nil {
			defer existingService.Close()
			err = existingService.Start()
			if err != nil {
				log.Printf("Varování při spouštění existující služby: %v", err)
			}
		}
		return nil
	}

	// Vytvoření služby a získání handleru
	s, err = m.CreateService(
		serviceName,
		exePath,
		mgr.Config{
			DisplayName:      serviceDisplayName,
			StartType:        mgr.StartAutomatic,
			ServiceStartName: "LocalSystem",
		},
	)

	if err != nil {
		log.Fatalln("chyba při vytváření handleru služby:", err)
		return err
	}

	defer s.Close()

	log.Printf("Služba %s byla úspěšně vytvořena", serviceName)

	// Spuštění služby s retry logikou
	for i := 0; i < 3; i++ {
		err = s.Start()
		if err == nil {
			log.Printf("Služba %s byla úspěšně spuštěna", serviceName)
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

func copyExecutable() error {
	// Získat cestu k aktuálnímu spustitelnému souboru
	sourcePath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return fmt.Errorf("chyba při získávání cesty k souboru: %v", err)
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
