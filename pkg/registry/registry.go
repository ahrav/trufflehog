// Package registry provides a centralized mechanism for managing detector prefilter rules.
// This package helps optimize secret scanning by allowing detectors to register rules
// that can be used to quickly filter out invalid matches before running more expensive
// regex checks.
//
// Detectors can supply a set of rules (via DetectorPrefilterConfig) that specify criteria
// such as minimum/maximum length, allowed characters, and optional prefixes. At runtime,
// the scanning engine retrieves these rules (as DetectorPrefilterCriteria) and applies them
// to candidate substrings before delegating to the actual detector logic.
// This approach reduces overhead by quickly filtering out invalid candidates.
package registry

import (
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// asciiSet is a 256-bit value (8 * 32 bits), but we only use the lower 128 bits for ASCII.
// Each bit represents whether a given ASCII character is in the set.
// The lower 16 bytes represent all ASCII chars (0-127).
// Non-ASCII chars will map outside the 128-bit range and will be effectively "not in the set."
// This provides very efficient O(1) character membership testing using bitwise operations.
type asciiSet [8]uint32

// contains reports whether c is inside the set by using bitwise operations
// to check if the corresponding bit is set in the lookup table.
// This approach was taken from the bytes package.
// https://cs.opensource.google/go/go/+/refs/tags/go1.23.4:src/bytes/bytes.go;l=899
func (as *asciiSet) contains(c byte) bool {
	return (as[c/32] & (1 << (c % 32))) != 0
}

// makeASCIISet creates a set of ASCII characters and reports whether all
// characters in chars are ASCII. It uses bit manipulation to create an efficient
// lookup table constructed at startup where each bit represents presence/absence of a character.
func makeASCIISet(chars string) (as asciiSet, ok bool) {
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if c >= utf8.RuneSelf { // non-ASCII char
			return as, false
		}
		// For each character, set the corresponding bit in the correct uint32.
		// c/32 determines which uint32 in the array.
		// c%32 determines which bit within that uint32.
		as[c/32] |= 1 << (c % 32)
	}
	return as, true
}

// DetectorPrefilterConfig defines a simple structure for authors of detectors to specify
// basic filtering criteria. These criteria help quickly eliminate candidates that
// cannot possibly match the detector's target secret format.
//
// All fields are optional. If a field is zero or empty, it imposes no corresponding
// constraint.
type DetectorPrefilterConfig struct {
	MinLength int // Minimum length of the candidate
	// MaxLength is the maximum number of characters the candidate can have.
	// Use 0 to indicate no upper bound.
	MaxLength int
	// AllowedChars defines a set of allowed characters. If non-empty, only these
	// characters may appear in the candidate. Detectors typically provide ASCII-only
	// strings, but if non-ASCII characters are included, a fallback mechanism is used.
	AllowedChars string
}

// DetectorPrefilterCriteria represents an optimized, runtime-ready version of the rules
// defined by DetectorPrefilterConfig. It is derived from DetectorPrefilterConfig during registration.
// Internal fields are structured for fast validation of candidates.
type DetectorPrefilterCriteria struct {
	// MinLength is the minimum length a candidate must have.
	MinLength int
	// MaxLength is the maximum length a candidate can have.
	// A value of 0 indicates no upper bound.
	MaxLength int

	// asciiOnly indicates that all allowed characters are ASCII, enabling a fast bitset lookup.
	asciiOnly bool
	// allowedASCII is a bitset representation of allowed ASCII characters.
	// Only valid if asciiOnly is true.
	allowedASCII asciiSet
	// allowedMap stores allowed characters for the fallback scenario when non-ASCII characters are present.
	// This is only used if asciiOnly is false.
	allowedMap map[rune]bool
}

// Matches checks whether the candidate meets all the detector prefilter rules.
// It returns true if the candidate satisfies all rules (length, prefix, allowed characters),
// or if no constraints are defined. Otherwise, it returns false.
//
// Matches is typically called by the scanning engine before running more expensive
// detection logic, such as regex evaluation or API verification.
func (c DetectorPrefilterCriteria) Matches(candidate []byte) bool {
	// If no length constraints are defined, we treat it as no minimum required.
	// For a credential, typically at least one of MinLength or MaxLength is set.
	minLen := c.MinLength
	if minLen == 0 && c.MaxLength > 0 {
		// If only MaxLength is set, minLen can be treated as MaxLength for the sake of finding a suitable run.
		minLen = c.MaxLength
	}

	// If no minLen or maxLen are set, just having a prefix and allowed chars might be enough.
	// In that case, just ensure chars are allowed (if specified).
	if minLen == 0 && c.MaxLength == 0 {
		return c.checkAllChars(candidate)
	}

	// We now attempt to find a run of allowed characters of at least minLen in the candidate.
	allowedCount := 0
	for i := 0; i < len(candidate); {
		r, size := utf8.DecodeRune(candidate[i:])
		if c.charAllowed(r) {
			allowedCount++
		} else {
			// Reset count if a disallowed char is encountered.
			allowedCount = 0
		}

		// If we've found a run of allowed characters at least minLen in length,
		// there's a potential credential substring here.
		if allowedCount >= minLen {
			return true
		}
		i += size
	}

	// No suitable run found that meets the minLen criterion.
	return false
}

// charAllowed checks if a single character is allowed by the constraints.
// This encapsulates logic for ASCII or map checks.
func (c DetectorPrefilterCriteria) charAllowed(ch rune) bool {
	if c.asciiOnly {
		// ASCII fast path.
		return ch < utf8.RuneSelf && c.allowedASCII.contains(byte(ch))
	} else if c.allowedMap != nil {
		// Fallback: non-ASCII.
		return c.allowedMap[ch]
	}
	// If no allowed chars set was defined, consider all chars allowed.
	return true
}

// checkAllChars verifies that all characters in candidate are allowed without
// enforcing any length-run logic. This is used if no length constraints are provided.
func (c DetectorPrefilterCriteria) checkAllChars(candidate []byte) bool {
	for _, ch := range candidate {
		if !c.charAllowed(rune(ch)) {
			return false
		}
	}
	return true
}

// detectorConstraints stores registered constraints for each DetectorType.
// By default, detectors may not have constraints, and thus won't be filtered.
var detectorConstraints = map[detectorspb.DetectorType]DetectorPrefilterCriteria{}

// RegisterConstraints allows detectors to register pre-check rules at startup.
// It takes a DetectorPrefilterConfig as input and transforms it into optimized DetectorPrefilterCriteria.
// This function should be called from an init function or a similar initialization block
// once per detector type.
func RegisterConstraints(dt detectorspb.DetectorType, rule DetectorPrefilterConfig) {
	c := DetectorPrefilterCriteria{
		MinLength: rule.MinLength,
		MaxLength: rule.MaxLength,
	}

	if rule.AllowedChars != "" {
		as, ok := makeASCIISet(rule.AllowedChars)
		if ok {
			// All allowed chars are ASCII, so use fast bitset.
			c.asciiOnly = true
			c.allowedASCII = as
		} else {
			// Non-ASCII present, fallback to map.
			c.allowedMap = make(map[rune]bool, len(rule.AllowedChars))
			for _, r := range rule.AllowedChars {
				c.allowedMap[r] = true
			}
		}
	}

	detectorConstraints[dt] = c
}

// GetConstraints returns the DetectorPrefilterCriteria associated with a DetectorType.
// If no constraints are registered for the given type, found will be false.
//
// The scanning engine uses this function to retrieve constraints before validating candidates.
func GetConstraints(dt detectorspb.DetectorType) (c DetectorPrefilterCriteria, found bool) {
	c, found = detectorConstraints[dt]
	return
}
