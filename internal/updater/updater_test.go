package updater

import (
	consts "KiskaLE/RustDesk-ID/internal/const"
	"net/http"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2.5.0", "2.5.0", 0},
		{"2.5", "2.5.0", 0},
		{"2.5.1", "2.5.0", 1},
		{"2.10.0", "2.9.0", 1},
		{"2.4.9", "2.5.0", -1},
		{" 2.5.0 ", "2.5.0", 0},
		// A prerelease is older than its release but newer than the previous release.
		{"2.5.0", "2.5.0-rc", 1},
		{"2.5.0-rc", "2.5.0", -1},
		{"2.5.0-rc", "2.4.9", 1},
		{"2.5.1-rc", "2.5.0", 1},
		{"2.5.0-rc", "2.5.0-rc", 0},
		// Prereleases among themselves, as in Semantic Versioning.
		{"2.5.0-rc", "2.5.0-rc.1", -1},
		{"2.5.0-rc.1", "2.5.0-rc.2", -1},
		{"2.5.0-rc.10", "2.5.0-rc.2", 1},
		{"2.5.0-alpha", "2.5.0-beta", -1},
		{"2.5.0-beta", "2.5.0-rc", -1},
		{"2.5.0-1", "2.5.0-alpha", -1},
		{"2.5.0-beta-2", "2.5.0-beta-10", 1},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := compareVersions(tt.b, tt.a); got != -tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestCheckUpdateHeader(t *testing.T) {
	tests := []struct {
		current, advertised string
		wantUpdate          bool
	}{
		{"2.5.0-rc", "2.5.0", true},
		{"2.5.0-rc", "2.5.0-rc.1", true},
		{"2.4.0", "2.5.0", true},
		{"2.5.0", "2.5.0", false},
		{"2.5.0", "2.5.0-rc", false},
		{"2.5.0", "2.4.0", false},
	}
	defer func(v string) { consts.Version = v }(consts.Version)
	for _, tt := range tests {
		consts.Version = tt.current
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("X-Client-Update", `{"version":"`+tt.advertised+`","id":"abc","hash":"00"}`)
		if got := CheckUpdateHeader(resp) != nil; got != tt.wantUpdate {
			t.Errorf("current %s, advertised %s: update = %v, want %v", tt.current, tt.advertised, got, tt.wantUpdate)
		}
	}
}

func TestGetInstallerExtension(t *testing.T) {
	tests := []struct {
		name        string
		signature   []byte
		id          string
		contentType string
		want        string
	}{
		{"msi signature with generic content type", append(append([]byte{}, msiSignature...), 0, 0), "abc", "application/octet-stream", ".msi"},
		{"exe signature wins over msi content type", []byte("MZ\x90\x00"), "abc", "application/x-msi", ".exe"},
		{"unknown signature falls back to content type", []byte("????"), "abc", "application/x-msi", ".msi"},
		{"unknown signature falls back to id suffix", nil, "abc.MSI", "", ".msi"},
		{"unknown signature defaults to exe", nil, "abc", "application/octet-stream", ".exe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getInstallerExtension(tt.signature, &UpdateInfo{ID: tt.id}, tt.contentType)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMsiexecCmdLine(t *testing.T) {
	got := msiexecCmdLine(`C:\Windows\Temp\fleetctrl-update-1.msi`, `C:\ProgramData\fleetctrl\logs\update-1.log`)
	want := `msiexec /i "C:\Windows\Temp\fleetctrl-update-1.msi" /qn /norestart /l*v "C:\ProgramData\fleetctrl\logs\update-1.log"`
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
