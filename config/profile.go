package config

import (
	"os"
	"strings"
	"sync"
)

// Profile represents an application deployment environment.
type Profile string

const (
	// ProfileDevelopment indicates local development environment.
	ProfileDevelopment Profile = "development"
	// ProfileTest indicates automated testing environment.
	ProfileTest Profile = "test"
	// ProfileStaging indicates pre-production staging environment.
	ProfileStaging Profile = "staging"
	// ProfileProduction indicates live production environment.
	ProfileProduction Profile = "production"
)

var (
	activeProfileMu sync.RWMutex
	currentProfile  Profile
)

// ParseProfile normalizes and returns the matching Profile.
// Recognizes common aliases:
// - "dev", "local", "development" -> ProfileDevelopment
// - "test", "testing" -> ProfileTest
// - "staging", "stage" -> ProfileStaging
// - "prod", "production" -> ProfileProduction
func ParseProfile(s string) Profile {
	cleaned := strings.ToLower(strings.TrimSpace(s))
	switch cleaned {
	case "dev", "development", "local":
		return ProfileDevelopment
	case "test", "testing":
		return ProfileTest
	case "stage", "staging":
		return ProfileStaging
	case "prod", "production":
		return ProfileProduction
	case "":
		return ProfileDevelopment
	default:
		return Profile(cleaned)
	}
}

// String returns the string representation of the Profile.
func (p Profile) String() string {
	if p == "" {
		return string(ProfileDevelopment)
	}
	return string(p)
}

// IsDevelopment reports whether the profile is development or local.
func (p Profile) IsDevelopment() bool {
	norm := ParseProfile(string(p))
	return norm == ProfileDevelopment
}

// IsTest reports whether the profile is automated testing.
func (p Profile) IsTest() bool {
	norm := ParseProfile(string(p))
	return norm == ProfileTest
}

// IsStaging reports whether the profile is staging/pre-production.
func (p Profile) IsStaging() bool {
	norm := ParseProfile(string(p))
	return norm == ProfileStaging
}

// IsProduction reports whether the profile is production.
func (p Profile) IsProduction() bool {
	norm := ParseProfile(string(p))
	return norm == ProfileProduction
}

// DetectProfile inspects process environment variables in order:
// 1. ZTATIC_ENV
// 2. APP_ENV
// 3. GO_ENV
// If none are specified, it defaults to ProfileDevelopment.
func DetectProfile() Profile {
	if env := os.Getenv("ZTATIC_ENV"); env != "" {
		return ParseProfile(env)
	}
	if env := os.Getenv("APP_ENV"); env != "" {
		return ParseProfile(env)
	}
	if env := os.Getenv("GO_ENV"); env != "" {
		return ParseProfile(env)
	}
	return ProfileDevelopment
}

// ActiveProfile returns the active runtime profile.
// If not explicitly set via SetProfile, it automatically detects from the environment.
func ActiveProfile() Profile {
	activeProfileMu.RLock()
	if currentProfile != "" {
		p := currentProfile
		activeProfileMu.RUnlock()
		return p
	}
	activeProfileMu.RUnlock()

	activeProfileMu.Lock()
	defer activeProfileMu.Unlock()
	if currentProfile == "" {
		currentProfile = DetectProfile()
	}
	return currentProfile
}

// SetProfile explicitly sets the active profile.
func SetProfile(p Profile) {
	activeProfileMu.Lock()
	defer activeProfileMu.Unlock()
	currentProfile = ParseProfile(string(p))
}

// ResetProfile resets the active profile cache to trigger re-detection.
func ResetProfile() {
	activeProfileMu.Lock()
	defer activeProfileMu.Unlock()
	currentProfile = ""
}
