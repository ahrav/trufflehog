//go:build detectors
// +build detectors

package detectors

import (
	"bytes"
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// Mock implementations for testing
type mockPatternDetector struct{}

func (m mockPatternDetector) FindCandidates(ctx context.Context, data []byte) ([]Candidate, error) {
	return nil, nil
}
func (m mockPatternDetector) Type() detectorspb.DetectorType { return detectorspb.DetectorType_Stripe }
func (m mockPatternDetector) Description() string            { return "Mock Detector" }

type mockVerifier struct{}

func (m mockVerifier) Verify(ctx context.Context, candidate Candidate) (bool, error) {
	return true, nil
}

func TestPrefixRegex(t *testing.T) {
	tests := []struct {
		keywords []string
		expected string
	}{
		{
			keywords: []string{"securitytrails"},
			expected: `(?i:securitytrails)(?:.|[\n\r]){0,40}?`,
		},
		{
			keywords: []string{"zipbooks"},
			expected: `(?i:zipbooks)(?:.|[\n\r]){0,40}?`,
		},
		{
			keywords: []string{"wrike"},
			expected: `(?i:wrike)(?:.|[\n\r]){0,40}?`,
		},
	}
	for _, tt := range tests {
		got := PrefixRegex(tt.keywords)
		if got != tt.expected {
			t.Errorf("PrefixRegex(%v) got: %v want: %v", tt.keywords, got, tt.expected)
		}
	}
}

func TestPrefixRegexKeywords(t *testing.T) {
	keywords := []string{"keyword1", "keyword2", "keyword3"}

	testCases := []struct {
		input    string
		expected bool
	}{
		{"keyword1 1234c4aabceeff4444442131444aab44", true},
		{"keyword1 1234567890ABCDEF1234567890ABBBCA", false},
		{"KEYWORD1 1234567890abcdef1234567890ababcd", true},
		{"KEYWORD1 1234567890ABCDEF1234567890ABdaba", false},
		{"keyword2 1234567890abcdef1234567890abeeff", true},
		{"keyword2 1234567890ABCDEF1234567890ABadbd", false},
		{"KEYWORD2 1234567890abcdef1234567890ababca", true},
		{"KEYWORD2 1234567890ABCDEF1234567890ABBBBs", false},
		{"keyword3 1234567890abcdef1234567890abccea", true},
		{"KEYWORD3 1234567890abcdef1234567890abaabb", true},
		{"keyword4 1234567890abcdef1234567890abzzzz", false},
		{"keyword3 1234567890ABCDEF1234567890AB", false},
		{"keyword4 1234567890ABCDEF1234567890AB", false},
	}

	keyPat := regexp.MustCompile(PrefixRegex(keywords) + `\b([0-9a-f]{32})\b`)

	for _, tc := range testCases {
		match := keyPat.MatchString(tc.input)
		if match != tc.expected {
			t.Errorf("Input: %s, Expected: %v, Got: %v", tc.input, tc.expected, match)
		}
	}
}

func BenchmarkPrefixRegex(b *testing.B) {
	kws := []string{"securitytrails"}
	for i := 0; i < b.N; i++ {
		PrefixRegex(kws)
	}
}

func TestDetectorPrefilterRulesMatches(t *testing.T) {
	tests := []struct {
		name       string
		rules      DetectorPrefilterCriteria
		candidate  []byte
		wantResult bool
	}{
		{
			name: "length constraints - valid run in middle",
			rules: DetectorPrefilterCriteria{
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
			rules: DetectorPrefilterCriteria{
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
			rules: DetectorPrefilterCriteria{
				MaxLength:    3,
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("x123x"),
			wantResult: true,
		},
		{
			name: "no length constraints - all chars must be valid",
			rules: DetectorPrefilterCriteria{
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("123"),
			wantResult: true,
		},
		{
			name: "no length constraints - one invalid char",
			rules: DetectorPrefilterCriteria{
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("123"); return set }(),
			},
			candidate:  []byte("12x3"),
			wantResult: false,
		},
		{
			name: "ascii chars - valid run with surrounding invalid chars",
			rules: DetectorPrefilterCriteria{
				MinLength:    3,
				asciiOnly:    true,
				allowedASCII: func() asciiSet { set, _ := makeASCIISet("abc123"); return set }(),
			},
			candidate:  []byte("xxabc123xx"),
			wantResult: true,
		},
		{
			name: "non-ascii chars - valid run",
			rules: DetectorPrefilterCriteria{
				MinLength:  3,
				asciiOnly:  false,
				allowedMap: map[rune]bool{'α': true, 'β': true, '∆': true, 'x': true},
			},
			candidate:  []byte("xxαβ∆xx"),
			wantResult: true,
		},
		{
			name: "non-ascii chars - longer valid run",
			rules: DetectorPrefilterCriteria{
				MinLength:  3,
				asciiOnly:  false,
				allowedMap: map[rune]bool{'a': true, 'b': true, '1': true, 'x': true, '∆': true},
			},
			candidate:  []byte("xxab1∆abxx"),
			wantResult: true,
		},
		{
			name:       "no constraints",
			rules:      DetectorPrefilterCriteria{},
			candidate:  []byte("anything"),
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rules.Matches(tt.candidate)
			assert.Equal(t, tt.wantResult, got, "IsEligible() failed for test case %s", tt.name)
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

func BenchmarkMatches(b *testing.B) {
	// Common test cases.
	asciiRules := DetectorPrefilterCriteria{
		MinLength:    5,
		asciiOnly:    true,
		allowedASCII: func() asciiSet { set, _ := makeASCIISet("abcdef123456"); return set }(),
	}

	nonAsciiRules := DetectorPrefilterCriteria{
		MinLength: 5,
		asciiOnly: false,
		allowedMap: map[rune]bool{
			'α': true, 'β': true, '∆': true,
			'a': true, 'b': true, 'c': true,
		},
	}

	noConstraints := DetectorPrefilterCriteria{}

	// Test data for larger inputs.
	validChars := []byte("abcdef123456")
	invalidChars := []byte("!@#$%^")
	sizes := []int{64, 512, 1024, 4096}

	benchCases := []struct {
		name      string
		rules     DetectorPrefilterCriteria
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
			rules     DetectorPrefilterCriteria
			candidate []byte
		}{
			name:      "large_input_valid_match_" + strconv.Itoa(size),
			rules:     asciiRules,
			candidate: makeTestData(size, validChars, invalidChars, 10),
		})

		// No match case - no valid runs long enough.
		benchCases = append(benchCases, struct {
			name      string
			rules     DetectorPrefilterCriteria
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
				_ = bc.rules.Matches(bc.candidate)
			}
		})
	}
}

func TestDetectorCatalog(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *detectorCatalog
		key     DetectorKey
		def     DetectorDefinition
		wantDef DetectorDefinition
		wantOk  bool
	}{
		{
			name:   "new catalog is empty",
			setup:  func() *detectorCatalog { return newCatalog() },
			key:    DetectorKey{},
			wantOk: false,
		},
		{
			name: "add and get detector definition",
			setup: func() *detectorCatalog {
				c := newCatalog()
				def := DetectorDefinition{
					Type:    detectorspb.DetectorType_Stripe,
					Version: 1,
				}
				c.Add(def)
				return c
			},
			key: DetectorKey{
				detectorType: detectorspb.DetectorType_Stripe,
				version:      1,
			},
			def: DetectorDefinition{
				Type:    detectorspb.DetectorType_Stripe,
				Version: 1,
			},
			wantDef: DetectorDefinition{
				Type:    detectorspb.DetectorType_Stripe,
				Version: 1,
			},
			wantOk: true,
		},
		{
			name:  "get non-existent detector",
			setup: func() *detectorCatalog { return newCatalog() },
			key: DetectorKey{
				detectorType: detectorspb.DetectorType_Stripe,
				version:      1,
			},
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.setup()
			got, ok := c.Get(tt.key)
			assert.Equal(t, tt.wantOk, ok)
			if tt.wantOk {
				assert.Equal(t, tt.wantDef, got)
			}
		})
	}
}

func TestRegisterDetector(t *testing.T) {
	tests := []struct {
		name        string
		setup       func()
		opts        DetectorRegistrationOptions
		shouldPanic bool
		wantType    detectorspb.DetectorType
		wantVersion int
		wantName    string
	}{
		{
			name: "basic registration",
			setup: func() {
				globalDetectorCatalog = newCatalog()
			},
			opts: DetectorRegistrationOptions{
				DetectorType:    detectorspb.DetectorType_Stripe,
				PatternDetector: mockPatternDetector{},
				Verifier:        mockVerifier{},
				Keywords:        []string{"test"},
			},
			wantType:    detectorspb.DetectorType_Stripe,
			wantVersion: 1,
		},
		{
			name: "registration with options",
			setup: func() {
				globalDetectorCatalog = newCatalog()
			},
			opts: DetectorRegistrationOptions{
				DetectorType:    detectorspb.DetectorType_AWS,
				Version:         2,
				CustomName:      "custom",
				PatternDetector: mockPatternDetector{},
				Verifier:        mockVerifier{},
				Keywords:        []string{"test"},
				PrefilterConfig: DetectorPrefilterConfig{
					MinLength:    10,
					MaxLength:    20,
					AllowedChars: "abcdef123456",
				},
			},
			wantType:    detectorspb.DetectorType_AWS,
			wantVersion: 2,
			wantName:    "custom",
		},
		{
			name: "unknown detector type",
			setup: func() {
				globalDetectorCatalog = newCatalog()
			},
			opts: DetectorRegistrationOptions{
				DetectorType: 0,
			},
			shouldPanic: true,
		},
		{
			name: "missing pattern detector",
			setup: func() {
				globalDetectorCatalog = newCatalog()
			},
			opts: DetectorRegistrationOptions{
				DetectorType: detectorspb.DetectorType_Stripe,
				Verifier:     mockVerifier{},
			},
			shouldPanic: true,
		},
		{
			name: "missing verifier",
			setup: func() {
				globalDetectorCatalog = newCatalog()
			},
			opts: DetectorRegistrationOptions{
				DetectorType:    detectorspb.DetectorType_Stripe,
				PatternDetector: mockPatternDetector{},
			},
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			if tt.shouldPanic {
				assert.Panics(t, func() {
					RegisterDetectorWithOptions(tt.opts)
				})
				return
			}

			RegisterDetectorWithOptions(tt.opts)
			def, err := GetDetectorDefinition(tt.wantType, tt.wantVersion, tt.wantName)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantType, def.Type)
			assert.Equal(t, tt.wantVersion, def.Version)
			assert.Equal(t, tt.wantName, def.CustomName)
		})
	}
}

func TestPrefilterCriteria(t *testing.T) {
	tests := []struct {
		name          string
		config        DetectorPrefilterConfig
		wantAsciiOnly bool
		wantAllowMap  bool
		checkChars    map[rune]bool
	}{
		{
			name: "ASCII-only allowed chars",
			config: DetectorPrefilterConfig{
				AllowedChars: "abc123",
			},
			wantAsciiOnly: true,
			wantAllowMap:  false,
		},
		{
			name: "non-ASCII allowed chars",
			config: DetectorPrefilterConfig{
				AllowedChars: "abc123日本語",
			},
			wantAsciiOnly: false,
			wantAllowMap:  true,
			checkChars: map[rune]bool{
				'a': true,
				'日': true,
			},
		},
		{
			name:          "empty allowed chars",
			config:        DetectorPrefilterConfig{},
			wantAsciiOnly: false,
			wantAllowMap:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criteria := convertConfigToCriteria(tt.config)
			assert.Equal(t, tt.wantAsciiOnly, criteria.asciiOnly)

			if tt.wantAllowMap {
				assert.NotNil(t, criteria.allowedMap)
				for r, want := range tt.checkChars {
					assert.Equal(t, want, criteria.allowedMap[r])
				}
			} else {
				assert.Nil(t, criteria.allowedMap)
			}
		})
	}
}
