// Command winres writes the Windows resources of the FleetCtrl service into
// cmd/main/rsrc_windows_amd64.syso, which go build links into
// fleetctrl-client.exe: version information, the icon, and an application
// manifest. Windows shows the version information in the file properties, and
// antivirus and application control rules can match it.
//
// Run it from the repository root before building the service:
//
//	go run ./scripts/winres -version 2.4.1
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	consts "KiskaLE/RustDesk-ID/internal/const"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

var versionPattern = regexp.MustCompile(`^\d+(\.\d+){0,3}$`)

// versionStrings are the texts in the Details tab of the file properties.
var versionStrings = map[string]string{
	version.CompanyName:      "FleetCtrl",
	version.ProductName:      "FleetCtrl",
	version.FileDescription:  "FleetCtrl client service",
	version.InternalName:     "fleetctrl-client",
	version.OriginalFilename: "fleetctrl-client.exe",
	version.LegalCopyright:   "Copyright © FleetCtrl",
}

func main() {
	ver := flag.String("version", consts.Version, "file and product version, MAJOR[.MINOR[.PATCH[.BUILD]]]")
	icon := flag.String("icon", filepath.Join("cmd", "ui", "build", "windows", "icon.ico"), "icon file (.ico)")
	out := flag.String("out", filepath.Join("cmd", "main", "rsrc_windows_amd64.syso"), "output object file")
	flag.Parse()

	if err := run(*ver, *icon, *out); err != nil {
		fmt.Fprintln(os.Stderr, "winres:", err)
		os.Exit(1)
	}
}

func run(ver, iconPath, out string) error {
	icon, err := os.Open(iconPath)
	if err != nil {
		return err
	}
	defer icon.Close()

	rs, err := buildResources(ver, icon)
	if err != nil {
		return err
	}

	f, err := os.Create(out)
	if err != nil {
		return err
	}
	if err := rs.WriteObject(f, winres.ArchAMD64); err != nil {
		f.Close()
		os.Remove(out)
		return fmt.Errorf("write %s: %w", out, err)
	}
	return f.Close()
}

func buildResources(ver string, icon io.ReadSeeker) (*winres.ResourceSet, error) {
	if err := validateVersion(ver); err != nil {
		return nil, err
	}
	rs := &winres.ResourceSet{}

	ico, err := winres.LoadICO(icon)
	if err != nil {
		return nil, fmt.Errorf("load icon: %w", err)
	}
	if err := rs.SetIcon(winres.Name("APP"), ico); err != nil {
		return nil, fmt.Errorf("set icon: %w", err)
	}

	var vi version.Info
	for key, value := range versionStrings {
		if err := vi.Set(version.LangDefault, key, value); err != nil {
			return nil, err
		}
	}
	vi.SetFileVersion(ver)
	vi.SetProductVersion(ver)
	rs.SetVersionInfo(vi)

	// Same execution level as without a manifest; declares Windows 10 support.
	rs.SetManifest(winres.AppManifest{
		Compatibility:  winres.Win10AndAbove,
		ExecutionLevel: winres.AsInvoker,
		DPIAwareness:   winres.DPIAware,
	})
	return rs, nil
}

// validateVersion accepts the versions that the fixed part of the version
// resource can hold: up to four numbers of at most 65535.
func validateVersion(v string) error {
	if !versionPattern.MatchString(v) {
		return fmt.Errorf("version %q is not MAJOR[.MINOR[.PATCH[.BUILD]]]", v)
	}
	for _, part := range strings.Split(v, ".") {
		if _, err := strconv.ParseUint(part, 10, 16); err != nil {
			return fmt.Errorf("version %q: %s is larger than 65535", v, part)
		}
	}
	return nil
}
