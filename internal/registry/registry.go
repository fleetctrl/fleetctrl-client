package registry

import (
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/windows/registry"
)

type RegisteryType string
type RegistryValue struct {
	Value any
	Type  RegisteryType
}

const (
	RegistryDword  RegisteryType = "DWORD"
	RegistryQword  RegisteryType = "QWORD"
	RegistryString RegisteryType = "STRING"
	RegistryBinary RegisteryType = "BINARY"
)

func CreateRegistryKey(registryType registry.Key, path string) error {
	var access uint32 = registry.ALL_ACCESS

	key, _, err := registry.CreateKey(registryType, path, access)
	if err != nil {
		return fmt.Errorf("failed to create registry key: %w", err)
	}
	defer key.Close()

	return nil
}

func SetRegisteryValue(registryType registry.Key, path string, name string, value RegistryValue) error {
	var access uint32 = registry.SET_VALUE | registry.QUERY_VALUE

	key, err := registry.OpenKey(registryType, path, access)
	if err != nil {
		return fmt.Errorf("failed to create registry key: %w", err)
	}
	defer key.Close()

	switch value.Type {
	case RegistryDword:
		if err = key.SetDWordValue(name, uint32(value.Value.(float64))); err != nil {
			return fmt.Errorf("failed to set registry value: %w", err)
		}
	case RegistryQword:
		if err = key.SetQWordValue(name, uint64(value.Value.(float64))); err != nil {
			return fmt.Errorf("failed to set registry value: %w", err)
		}
	case RegistryBinary:
		if err = key.SetBinaryValue(name, value.Value.([]byte)); err != nil {
			return fmt.Errorf("failed to set registry value: %w", err)
		}
	case RegistryString:
		if err = key.SetStringValue(name, value.Value.(string)); err != nil {
			return fmt.Errorf("failed to set registry value: %w", err)
		}
	}

	return nil
}

func GetRegisteryValue(registryType registry.Key, path string, name string) (string, error) {
	var access uint32 = registry.QUERY_VALUE

	key, err := registry.OpenKey(registryType, path, access)
	if err != nil {
		return "", fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	value, _, err := key.GetStringValue(name)
	if err == nil {
		return value, nil
	}

	intValue, _, err := key.GetIntegerValue(name)
	if err == nil {
		return strconv.FormatUint(intValue, 10), nil
	}

	return "", fmt.Errorf("failed to get registry value: %w", err)
}

func GetOptionalRegisteryValue(registryType registry.Key, path string, name string) (string, bool, error) {
	value, err := GetRegisteryValue(registryType, path, name)
	if err == nil {
		return value, true, nil
	}
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	return "", false, err
}

func DeleteRegisteryValue(registryType registry.Key, path string, name string) error {
	var access uint32 = registry.SET_VALUE

	key, err := registry.OpenKey(registryType, path, access)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	if err := key.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("failed to delete registry value: %w", err)
	}

	return nil
}
