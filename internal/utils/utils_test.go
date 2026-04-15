package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseJSON(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		type payload struct {
			Name string `json:"name"`
		}

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"fleetctrl"}`))
		var got payload

		require.NoError(t, ParseJSON(req, &got))
		assert.Equal(t, "fleetctrl", got.Name)
	})

	t.Run("missing body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Body = nil

		assert.Error(t, ParseJSON(req, &struct{}{}))
	})
}

func TestParseHttpError(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(`{"error":"broken"}`))}
	assert.Equal(t, "broken", ParseHttpError(resp))

	resp = &http.Response{Body: io.NopCloser(strings.NewReader(`not-json`))}
	assert.Empty(t, ParseHttpError(resp))
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()

	require.NoError(t, WriteJSON(rr, http.StatusCreated, map[string]string{"status": "ok"}))
	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), `"status":"ok"`)
}

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()

	require.NoError(t, WriteError(rr, http.StatusBadRequest, io.EOF))
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), `"error":"EOF"`)
}

func TestCalculateFileHash(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "sample.txt")
	content := []byte("fleetctrl")

	require.NoError(t, os.WriteFile(filePath, content, 0644))

	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	got, err := CalculateFileHash(filePath)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestCopy(t *testing.T) {
	var dst bytes.Buffer
	written, err := Copy(&dst, strings.NewReader("abc"))
	require.NoError(t, err)
	assert.Equal(t, int64(3), written)
	assert.Equal(t, "abc", dst.String())
}
