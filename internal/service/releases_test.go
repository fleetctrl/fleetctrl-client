package service

import (
	"KiskaLE/RustDesk-ID/internal/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelectNewestReleaseUsesHighestVersionRegardlessOfOrder(t *testing.T) {
	releases := []models.AssignedRelease{
		{ID: "old-last", Version: "1.0.0"},
		{ID: "new-middle", Version: "2.0.0"},
		{ID: "older-tail", Version: "1.5.0"},
	}

	selected := selectNewestRelease(releases)

	assert.Equal(t, "new-middle", selected.ID)
	assert.Equal(t, "2.0.0", selected.Version)
}

func TestSelectNewestReleasePrefersVersionedReleaseOverEmptyVersion(t *testing.T) {
	releases := []models.AssignedRelease{
		{ID: "empty", Version: ""},
		{ID: "versioned", Version: "1.0.0"},
	}

	selected := selectNewestRelease(releases)

	assert.Equal(t, "versioned", selected.ID)
}
