package registry

import (
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
