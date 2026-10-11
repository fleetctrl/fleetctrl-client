package updater

import "testing"

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
