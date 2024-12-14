package registry

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDetectorPrefilterRulesIsEligible(t *testing.T) {
	tests := []struct {
		name       string
		rules      DetectorPrefilterRules
		candidate  []byte
		wantResult bool
	}{
		{
			name: "length constraints - valid run in middle",
			rules: DetectorPrefilterRules{
				MinLength:    3,
				MaxLength:    5,
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("ab123xy"),
			wantResult: true,
		},
		{
			name: "length constraints - no valid run",
			rules: DetectorPrefilterRules{
				MinLength:    3,
				MaxLength:    5,
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("12xy12"),
			wantResult: false,
		},
		{
			name: "max length only - treated as min length",
			rules: DetectorPrefilterRules{
				MaxLength:    3,
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("x123x"),
			wantResult: true,
		},
		{
			name: "no length constraints - all chars must be valid",
			rules: DetectorPrefilterRules{
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("123"),
			wantResult: true,
		},
		{
			name: "no length constraints - one invalid char",
			rules: DetectorPrefilterRules{
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("12x3"),
			wantResult: false,
		},
		{
			name: "ascii chars - valid run with surrounding invalid chars",
			rules: DetectorPrefilterRules{
				MinLength:    3,
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("abc123"); return set }(),
			},
			candidate:  []byte("xxabc123xx"),
			wantResult: true,
		},
		{
			name: "non-ascii chars - valid run",
			rules: DetectorPrefilterRules{
				MinLength:  3,
				asciiOnly:  false,
				allowedMap: map[rune]bool{'α': true, 'β': true, '∆': true, 'x': true},
			},
			candidate:  []byte("xxαβ∆xx"),
			wantResult: true,
		},
		{
			name: "non-ascii chars - longer valid run",
			rules: DetectorPrefilterRules{
				MinLength:  3,
				asciiOnly:  false,
				allowedMap: map[rune]bool{'a': true, 'b': true, '1': true, 'x': true, '∆': true},
			},
			candidate:  []byte("xxab1∆abxx"),
			wantResult: true,
		},
		{
			name:       "no constraints",
			rules:      DetectorPrefilterRules{},
			candidate:  []byte("anything"),
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rules.IsEligible(tt.candidate)
			assert.Equal(t, tt.wantResult, got, "IsEligible() failed for test case %s", tt.name)
		})
	}
}

func TestRegisterAndGetConstraints(t *testing.T) {
	tests := []struct {
		name           string
		detectorType   detectorspb.DetectorType
		rule           DetectorPrefilterRule
		wantFound      bool
		checkCandidate []byte
		wantEligible   bool
	}{
		{
			name:         "basic registration",
			detectorType: detectorspb.DetectorType_AWS,
			rule: DetectorPrefilterRule{
				MinLength:    5,
				MaxLength:    10,
				AllowedChars: "abc123",
			},
			wantFound:      true,
			checkCandidate: []byte("abc123"),
			wantEligible:   true,
		},
		{
			name:         "non-registered detector",
			detectorType: detectorspb.DetectorType_AWS,
			wantFound:    false,
		},
		{
			name:           "empty rule",
			detectorType:   detectorspb.DetectorType_AWS,
			rule:           DetectorPrefilterRule{},
			wantFound:      true,
			checkCandidate: []byte("anything"),
			wantEligible:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear any existing constraints.
			detectorConstraints = map[detectorspb.DetectorType]DetectorPrefilterRules{}

			if tt.wantFound {
				RegisterConstraints(tt.detectorType, tt.rule)
			}

			rules, found := GetConstraints(tt.detectorType)
			assert.Equal(t, tt.wantFound, found, "failed to get constraints")

			if found && tt.checkCandidate != nil {
				got := rules.IsEligible(tt.checkCandidate)
				assert.Equal(t, tt.wantEligible, got, "failed to check if candidate is eligible")
			}
		})
	}
}

// makeTestData creates a byte slice of specified size with a pattern of valid and invalid chars
func makeTestData(size int, validChars, invalidChars []byte, validRunLength int) []byte {
	buf := bytes.Buffer{}
	buf.Grow(size)

	// Create a pattern that alternates between valid and invalid characters
	for buf.Len() < size {
		// Add a run of valid characters
		for i := 0; i < validRunLength && buf.Len() < size; i++ {
			buf.WriteByte(validChars[i%len(validChars)])
		}
		// Add some invalid characters
		for i := 0; i < 3 && buf.Len() < size; i++ {
			buf.WriteByte(invalidChars[i%len(invalidChars)])
		}
	}

	return buf.Bytes()
}

func BenchmarkIsEligible(b *testing.B) {
	// Common test cases.
	asciiRules := DetectorPrefilterRules{
		MinLength:    5,
		asciiOnly:    true,
		allowedASCII: func() asciiSet { set, _ := makeASCIISet("abcdef123456"); return set }(),
	}

	nonAsciiRules := DetectorPrefilterRules{
		MinLength: 5,
		asciiOnly: false,
		allowedMap: map[rune]bool{
			'α': true, 'β': true, '∆': true,
			'a': true, 'b': true, 'c': true,
		},
	}

	noConstraints := DetectorPrefilterRules{}

	// Test data for larger inputs.
	validChars := []byte("abcdef123456")
	invalidChars := []byte("!@#$%^")
	sizes := []int{64, 512, 1024, 4096}

	benchCases := []struct {
		name      string
		rules     DetectorPrefilterRules
		candidate []byte
	}{
		{
			name:      "ascii_only_valid_match",
			rules:     asciiRules,
			candidate: []byte("test123abc"),
		},
		{
			name:      "ascii_only_no_match",
			rules:     asciiRules,
			candidate: []byte("test!!!abc"),
		},
		{
			name:      "non_ascii_valid_match",
			rules:     nonAsciiRules,
			candidate: []byte("αβ∆abc"),
		},
		{
			name:      "non_ascii_no_match",
			rules:     nonAsciiRules,
			candidate: []byte("xyz123"),
		},
		{
			name:      "no_constraints",
			rules:     noConstraints,
			candidate: []byte("anything goes here!@#"),
		},
		{
			name:      "long_input_valid_match",
			rules:     asciiRules,
			candidate: []byte("prefix_abc123def_suffix_making_this_longer"),
		},
		{
			name:      "long_input_no_match",
			rules:     asciiRules,
			candidate: []byte("prefix_###_suffix_making_this_longer_without_valid_chars"),
		},
	}

	// Add large input test cases.
	for _, size := range sizes {
		// Valid match case - contains valid runs.
		benchCases = append(benchCases, struct {
			name      string
			rules     DetectorPrefilterRules
			candidate []byte
		}{
			name:      "large_input_valid_match_" + strconv.Itoa(size),
			rules:     asciiRules,
			candidate: makeTestData(size, validChars, invalidChars, 10),
		})

		// No match case - no valid runs long enough.
		benchCases = append(benchCases, struct {
			name      string
			rules     DetectorPrefilterRules
			candidate []byte
		}{
			name:      "large_input_no_match_" + strconv.Itoa(size),
			rules:     asciiRules,
			candidate: makeTestData(size, validChars, invalidChars, 2), // runs too short to match
		})
	}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(bc.candidate)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = bc.rules.IsEligible(bc.candidate)
			}
		})
	}
}
