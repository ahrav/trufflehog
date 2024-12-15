package detectors

import (
	"context"
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// DetectorKey is used to identify a detector in the keywordsToDetectors map.
// Multiple detectors can have the same detector type but different versions.
// This allows us to identify a detector by its type and version. An
// additional (optional) field is provided to disambiguate multiple custom
// detectors. This type is exported even though none of its fields are so
// that the AhoCorasickCore can populate passed-in maps keyed on this type
// without exposing any of its internals to consumers.
type DetectorKey struct {
	detectorType       detectorspb.DetectorType
	version            int
	customDetectorName string
}

// DetectorDefinition encapsulates all the components and configuration needed for a detector.
// This includes pattern matching, verification, and filtering criteria.
// It serves as the complete specification for how to detect and verify a particular type of secret.
type DetectorDefinition struct {
	Type              detectorspb.DetectorType
	Version           int
	CustomName        string
	PrefilterCriteria DetectorPrefilterCriteria
	PatternDetector   PatternDetector
	Verifier          Verifier
	Keywords          []string
}

// detectorCatalog maintains a registry of all detector definitions, allowing lookup
// by detector key
// This centralized catalog ensures consistent detector behavior across the application.
type detectorCatalog struct {
	byKey map[DetectorKey]DetectorDefinition
}

func newCatalog() *detectorCatalog {
	return &detectorCatalog{
		byKey: make(map[DetectorKey]DetectorDefinition),
	}
}

// globalDetectorCatalog is the singleton instance used for all detector registration.
var globalDetectorCatalog = newCatalog()

// Add adds a new detector definition to the catalog.
func (c *detectorCatalog) Add(def DetectorDefinition) {
	key := DetectorKey{
		detectorType:       def.Type,
		version:            def.Version,
		customDetectorName: def.CustomName,
	}
	c.byKey[key] = def
}

// Get retrieves a specific detector definition by its type, version, and optional custom name.
// Returns an error if the requested definition is not found in the catalog.
func (c *detectorCatalog) Get(key DetectorKey) (DetectorDefinition, bool) {
	def, ok := c.byKey[key]
	return def, ok
}

// GetDefaultDetectorDefinition retrieves the default (version 1) definition for a detector type.
// This is a convenience wrapper around GetDetectorDefinition for the common case.
func GetDefaultDetectorDefinition(dt detectorspb.DetectorType) (DetectorDefinition, error) {
	return GetDetectorDefinition(dt, 1, "")
}

// GetDetectorDefinition retrieves a specific detector definition by its type, version, and optional custom name.
// Returns an error if the requested definition is not found in the catalog.
func GetDetectorDefinition(dt detectorspb.DetectorType, version int, customName string) (DetectorDefinition, error) {
	key := DetectorKey{dt, version, customName}
	def, ok := globalDetectorCatalog.Get(key)
	if !ok {
		return DetectorDefinition{}, fmt.Errorf("detector definition not found for type %v version %d name %q", dt, version, customName)
	}
	return def, nil
}

// RegisterDetector provides backward compatibility for registering detectors without explicit prefilter configuration.
func RegisterDetector(
	dt detectorspb.DetectorType,
	pd PatternDetector,
	v Verifier,
	keywords []string,
) {
	RegisterDetectorWithOptions(DetectorRegistrationOptions{
		DetectorType:    dt,
		PatternDetector: pd,
		Verifier:        v,
		Keywords:        keywords,
	})
}

// DetectorRegistrationOptions provides a flexible way to configure a detector during registration.
// This allows for future extensibility without breaking existing detector registrations.
type DetectorRegistrationOptions struct {
	DetectorType    detectorspb.DetectorType
	Version         int
	CustomName      string
	PrefilterConfig DetectorPrefilterConfig
	PatternDetector PatternDetector
	Verifier        Verifier
	Keywords        []string
}

// RegisterDetectorWithOptions registers a new detector with the global catalog using the provided options.
// It performs validation of required fields and converts the prefilter configuration into criteria.
func RegisterDetectorWithOptions(opts DetectorRegistrationOptions) {
	if opts.DetectorType == 0 {
		panic("detector type cannot be UNKNOWN")
	}
	if opts.PatternDetector == nil {
		panic("pattern detector cannot be nil")
	}
	if opts.Verifier == nil {
		panic("verifier cannot be nil")
	}

	if opts.Version == 0 {
		opts.Version = 1
	}

	criteria := convertConfigToCriteria(opts.PrefilterConfig)
	def := DetectorDefinition{
		Type:              opts.DetectorType,
		Version:           opts.Version,
		CustomName:        opts.CustomName,
		PrefilterCriteria: criteria,
		PatternDetector:   opts.PatternDetector,
		Verifier:          opts.Verifier,
		Keywords:          opts.Keywords,
	}
	globalDetectorCatalog.Add(def)
}

// convertConfigToCriteria transforms a PrefilterConfig into PrefilterCriteria,
// optimizing for ASCII-only character sets when possible.
func convertConfigToCriteria(cfg DetectorPrefilterConfig) DetectorPrefilterCriteria {
	c := DetectorPrefilterCriteria{
		MinLength: cfg.MinLength,
		MaxLength: cfg.MaxLength,
	}

	if cfg.AllowedChars != "" {
		as, ok := makeASCIISet(cfg.AllowedChars)
		if ok {
			c.asciiOnly = true
			c.allowedASCII = as
		} else {
			c.allowedMap = make(map[rune]bool, len(cfg.AllowedChars))
			for _, r := range cfg.AllowedChars {
				c.allowedMap[r] = true
			}
		}
	}

	return c
}

// Candidate represents a potential secret that has been detected but not yet verified.
// It contains both the raw secret data and metadata about the detection.
type Candidate struct {
	Raw       []byte
	RawV2     []byte
	Redacted  string
	ExtraData map[string]string
}

// toResult converts a Candidate into a Result by adding the detector type.
// This is used internally when a detector needs to return its findings.
func (c Candidate) toResult(dt detectorspb.DetectorType) Result {
	return Result{
		DetectorType: dt,
		Raw:          c.Raw,
		RawV2:        c.RawV2,
		Redacted:     c.Redacted,
		ExtraData:    c.ExtraData,
	}
}

// PatternDetector defines the interface for secret detection logic.
// Implementations of this interface handle the pattern matching and extraction
// of candidates.
type PatternDetector interface {
	// FindCandidates scans the input data and returns any candidates found.
	FindCandidates(ctx context.Context, data []byte) ([]Candidate, error)
	// Type returns the specific type of detector (e.g. AWS, GitHub, etc).
	Type() detectorspb.DetectorType
	// Description returns human-readable information about what this detector looks for.
	Description() string
}

// Verifier defines the interface for secret verification logic.
// Implementations handle validating whether a detected secret is valid
// by making API calls or other verification steps. (eg db connection)
type Verifier interface {
	// Verify checks if a candidate secret is valid and currently active.
	// Returns true if the secret is verified as valid.
	Verify(ctx context.Context, candidate Candidate) (bool, error)
}

// PatternBasedDetector is an adapter that implements the old Detector interface.
// It is used to implement new detectors while keeping the old interface for backwards compatibility.
// It maintains backward compatibility by using the old interface's methods, but delegates the actual
// detection logic to the patternDetector and verifier.
//
// This is a temporary adapter to help with the transition to the new detector interface.
// It will be removed once all detectors have been updated to the new interface.
type PatternBasedDetector struct {
	Detector          PatternDetector
	Verifier          Verifier
	KeywordList       []string
	PrefilterCriteria DetectorPrefilterCriteria
}

// Keywords returns the keywords for the detector.
func (p PatternBasedDetector) Keywords() []string { return p.KeywordList }

// Type returns the DetectorType number from detectors.proto for the given detector.
func (p PatternBasedDetector) Type() detectorspb.DetectorType { return p.Detector.Type() }

// Description returns a description for the result being detected
func (p PatternBasedDetector) Description() string { return p.Detector.Description() }

// FromData will scan bytes for results, and optionally verify them.
// This is the old Detector interface's FromData method.
func (p PatternBasedDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	if !p.PrefilterCriteria.Matches(data) {
		return nil, nil
	}

	var finalResults []Result
	detectedCandidates, err := p.Detector.FindCandidates(ctx, data)
	if err != nil {
		return nil, err
	}

	for _, c := range detectedCandidates {
		res := c.toResult(p.Detector.Type())
		if verify {
			ok, verr := p.Verifier.Verify(ctx, c)
			if verr != nil {
				res.SetVerificationError(verr, string(c.Raw))
			}
			res.Verified = ok
			if ok {
				finalResults = append(finalResults, res)
			}
		} else {
			// Without verification, just return what we found.
			finalResults = append(finalResults, res)
		}
	}

	return finalResults, nil
}
