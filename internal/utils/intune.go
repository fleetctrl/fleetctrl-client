package utils

import (
	"golang.org/x/sys/windows/registry"
)

// GetIntuneID retrieves the Azure AD Tenant ID from Intune enrollment in the Windows registry.
// Returns empty string if the device is not enrolled in Intune.
func GetIntuneID() (string, error) {
	// Open the Enrollments registry key
	enrollmentsKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		// Key doesn't exist - device is not enrolled
		return "", nil
	}
	defer enrollmentsKey.Close()

	// Get all subkeys (enrollment GUIDs)
	subkeys, err := enrollmentsKey.ReadSubKeyNames(-1)
	if err != nil {
		return "", nil
	}

	// Iterate through each enrollment subkey
	for _, subkey := range subkeys {
		enrollmentKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments\`+subkey, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// Check if UPN exists (indicates Intune enrollment)
		upn, _, err := enrollmentKey.GetStringValue("UPN")
		if err != nil || upn == "" {
			enrollmentKey.Close()
			continue
		}

		// UPN exists, get the AADTenantID
		tenantID, _, err := enrollmentKey.GetStringValue("AADTenantID")
		enrollmentKey.Close()

		if err == nil && tenantID != "" {
			return tenantID, nil
		}
	}

	// No Intune enrollment found
	return "", nil
}
