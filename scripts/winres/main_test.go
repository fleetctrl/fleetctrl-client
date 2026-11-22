package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func TestBuildResources(t *testing.T) {
	icon, err := os.Open(filepath.Join("..", "..", "cmd", "ui", "build", "windows", "icon.ico"))
	require.NoError(t, err)
	defer icon.Close()

	rs, err := buildResources("2.4.1", icon)
	require.NoError(t, err)

	vi, err := version.FromBytes(rs.Get(winres.RT_VERSION, winres.ID(1), version.LangDefault))
	require.NoError(t, err)
	assert.Equal(t, [4]uint16{2, 4, 1, 0}, vi.FileVersion)
	assert.Equal(t, [4]uint16{2, 4, 1, 0}, vi.ProductVersion)
	table := vi.Table().GetMainTranslation()
	for key, value := range versionStrings {
		assert.Equal(t, value, table[key], key)
	}
	assert.Equal(t, "2.4.1", table[version.FileVersion])
	assert.Equal(t, "2.4.1", table[version.ProductVersion])

	manifest := rs.Get(winres.RT_MANIFEST, winres.ID(1), winres.LCIDDefault)
	assert.Contains(t, string(manifest), `level="asInvoker"`)

	_, err = rs.GetIcon(winres.Name("APP"))
	assert.NoError(t, err)

	var object bytes.Buffer
	require.NoError(t, rs.WriteObject(&object, winres.ArchAMD64))
	const imageFileMachineAMD64 = 0x8664
	assert.Equal(t, uint16(imageFileMachineAMD64), binary.LittleEndian.Uint16(object.Bytes()))
}

func TestValidateVersion(t *testing.T) {
	for _, v := range []string{"2", "2.4", "2.4.1", "2.4.1.7", "65535.0.0"} {
		assert.NoError(t, validateVersion(v), v)
	}
	for _, v := range []string{"", "v2.4.1", "2.4.1-beta", "2.4.1.7.8", "2..1", "65536.0.0"} {
		assert.Error(t, validateVersion(v), v)
	}
}
