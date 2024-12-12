// Package registry provides a centralized mechanism for managing detector prefilter rules.
// This package helps optimize secret scanning by allowing detectors to register constraints
// that can be used to quickly filter out invalid matches before running more expensive
// regex checks.
package registry

import "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

// DetectorPrefilterRules defines the constraints that can be used to pre-filter potential
// secret matches. These rules help reduce false positives and improve performance by
// filtering out invalid matches early in the detection process.
type DetectorPrefilterRules struct {
	MinLength    int    // Minimum length of the secret
	MaxLength    int    // Maximum length of the secret
	AllowedChars string // Allowed characters in the secret
	KnownPrefix  string // Known prefix that must appear before the secret
}

var detectorConstraints = map[detectorspb.DetectorType]DetectorPrefilterRules{}

// RegisterConstraints associates a set of prefilter rules with a specific detector type.
// This allows detectors to define their filtering criteria which can be used to optimize
// the scanning process by quickly rejecting invalid matches.
func RegisterConstraints(dt detectorspb.DetectorType, c DetectorPrefilterRules) {
	detectorConstraints[dt] = c
}

// GetConstraints retrieves the prefilter rules for a given detector type.
// Returns the rules and a boolean indicating whether rules were found for the detector.
// This is used during the scanning process to apply any registered constraints before
// performing more detailed secret verification.
func GetConstraints(dt detectorspb.DetectorType) (DetectorPrefilterRules, bool) {
	c, found := detectorConstraints[dt]
	return c, found
}
