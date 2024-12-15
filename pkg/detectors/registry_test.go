package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

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
