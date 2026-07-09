package service

import (
	"KiskaLE/RustDesk-ID/internal/apps"
	"KiskaLE/RustDesk-ID/internal/models"
)

func selectNewestRelease(releases []models.AssignedRelease) models.AssignedRelease {
	newest := releases[0]
	for _, release := range releases[1:] {
		if isNewerRelease(release, newest) {
			newest = release
		}
	}
	return newest
}

func isNewerRelease(candidate, current models.AssignedRelease) bool {
	if candidate.Version == "latest" {
		return current.Version != "latest"
	}
	if current.Version == "latest" {
		return false
	}
	if candidate.Version == "" {
		return current.Version == ""
	}
	if current.Version == "" {
		return true
	}
	return apps.CompareVersions(candidate.Version, current.Version) > 0
}
