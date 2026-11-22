package utils

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetFileVersion returns the FileVersion string from the version resource of
// the file, the value PowerShell shows as (Get-Item path).VersionInfo.FileVersion.
// If the resource has no such string, it returns the binary file version,
// such as "1.2.3.4".
func GetFileVersion(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil {
		return "", err
	}
	if size == 0 {
		return "", errors.New("file has no version resource")
	}
	info := versionInfo(make([]byte, size))
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&info[0])); err != nil {
		return "", err
	}

	for _, table := range info.stringTables() {
		if v := info.query(`\StringFileInfo\` + table + `\FileVersion`); v != "" {
			return v, nil
		}
	}
	return info.fixedFileVersion()
}

// versionInfo is a VS_VERSIONINFO block read by GetFileVersionInfo.
type versionInfo []byte

// stringTables lists the string tables to search in the order .NET's
// FileVersionInfo uses: the first translation of the file, then US English
// with the Unicode, Windows-1252, and neutral code pages.
func (vi versionInfo) stringTables() []string {
	var tables []string
	var p unsafe.Pointer
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&vi[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&p), &n); err == nil && n >= 4 && vi.contains(p, uintptr(n)) {
		lang := *(*uint16)(p)
		codePage := *(*uint16)(unsafe.Add(p, 2))
		tables = append(tables, fmt.Sprintf("%04x%04x", lang, codePage))
	}
	return append(tables, "040904b0", "040904e4", "04090000")
}

// query returns a string value of the block, or "" if there is none.
func (vi versionInfo) query(subBlock string) string {
	var p unsafe.Pointer
	var n uint32 // characters, including the terminating NUL
	if err := windows.VerQueryValue(unsafe.Pointer(&vi[0]), subBlock, unsafe.Pointer(&p), &n); err != nil || n == 0 {
		return ""
	}
	if !vi.contains(p, uintptr(n)*2) {
		return ""
	}
	return strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(p), n)))
}

func (vi versionInfo) fixedFileVersion() (string, error) {
	var p unsafe.Pointer
	var n uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&vi[0]), `\`, unsafe.Pointer(&p), &n); err != nil {
		return "", err
	}
	fixed := (*windows.VS_FIXEDFILEINFO)(p)
	if uintptr(n) < unsafe.Sizeof(*fixed) || !vi.contains(p, unsafe.Sizeof(*fixed)) {
		return "", errors.New("version resource has no file version")
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		fixed.FileVersionMS>>16, fixed.FileVersionMS&0xffff,
		fixed.FileVersionLS>>16, fixed.FileVersionLS&0xffff), nil
}

// contains reports whether size bytes at p lie within the block, so that a
// malformed resource cannot make us read past it.
func (vi versionInfo) contains(p unsafe.Pointer, size uintptr) bool {
	start := uintptr(unsafe.Pointer(&vi[0]))
	addr := uintptr(p)
	return addr >= start && addr+size <= start+uintptr(len(vi))
}
