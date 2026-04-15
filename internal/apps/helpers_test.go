package apps

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

func TestFindReleaseScriptByPhase(t *testing.T) {
	scripts := []models.ReleaseScript{
		{ID: "before-1", Phase: "before_install", ScriptName: "before.ps1"},
		{ID: "after-1", Phase: "after_install", ScriptName: "after.ps1"},
	}

	matched := findReleaseScriptByPhase(scripts, "AFTER_INSTALL")
	require.NotNil(t, matched)
	assert.Equal(t, "after-1", matched.ID)

	missing := findReleaseScriptByPhase(scripts, "rollback")
	assert.Nil(t, missing)
}

func TestValidateWingetID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid simple", input: "Microsoft.PowerToys"},
		{name: "valid symbols", input: "Vendor.App_1+beta"},
		{name: "empty", input: "", wantErr: true},
		{name: "invalid spaces", input: "Vendor App", wantErr: true},
		{name: "invalid slash", input: "Vendor/App", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWingetID(tt.input)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestValidateWingetVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "empty allowed", input: ""},
		{name: "latest allowed", input: "latest"},
		{name: "valid version", input: "1.2.3-beta+1"},
		{name: "invalid spaces", input: "1.2 3", wantErr: true},
		{name: "invalid slash", input: "1.2/3", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWingetVersion(tt.input)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestUpsertEnv(t *testing.T) {
	t.Run("replaces existing entry case-insensitively", func(t *testing.T) {
		input := []string{"Path=C:\\Windows", "TEMP=C:\\Temp"}

		got := upsertEnv(input, "PATH", "C:\\Apps")
		want := []string{"PATH=C:\\Apps", "TEMP=C:\\Temp"}

		assert.Equal(t, want, got)
	})

	got := upsertEnv([]string{"TEMP=C:\\Temp"}, "PATH", "C:\\Apps")
	assert.Equal(t, []string{"TEMP=C:\\Temp", "PATH=C:\\Apps"}, got)
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want int
	}{
		{name: "equal", v1: "1.2.3", v2: "1.2.3", want: 0},
		{name: "less than", v1: "1.2.3", v2: "1.2.4", want: -1},
		{name: "greater than", v1: "2.0.0", v2: "1.9.9", want: 1},
		{name: "dash treated as separator", v1: "1.2-3", v2: "1.2.3", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CompareVersions(tt.v1, tt.v2))
		})
	}
}

func TestParseRegistryPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKey registry.Key
		want    string
	}{
		{name: "HKLM short", input: `HKLM\Software\FleetCtrl`, wantKey: registry.LOCAL_MACHINE, want: `Software\FleetCtrl`},
		{name: "HKCU long", input: `HKEY_CURRENT_USER/Software/FleetCtrl`, wantKey: registry.CURRENT_USER, want: `Software\FleetCtrl`},
		{name: "HKCR short", input: `HKCR\Installer\Products`, wantKey: registry.CLASSES_ROOT, want: `Installer\Products`},
		{name: "default fallback", input: `Software\FleetCtrl`, wantKey: registry.LOCAL_MACHINE, want: `Software\FleetCtrl`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotPath := ParseRegistryPath(tt.input)
			assert.Equal(t, tt.wantKey, gotKey)
			assert.Equal(t, tt.want, gotPath)
		})
	}
}
