package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDetectorConstraints(t *testing.T) {
	tests := []struct {
		name           string
		detectorType   detectorspb.DetectorType
		rules          DetectorPrefilterRules
		wantRules      DetectorPrefilterRules
		wantFound      bool
		shouldRegister bool
	}{
		{
			name:         "unregistered detector returns not found",
			detectorType: detectorspb.DetectorType_AWS,
			wantFound:    false,
		},
		{
			name:         "register and retrieve rules",
			detectorType: detectorspb.DetectorType_Slack,
			rules: DetectorPrefilterRules{
				MinLength:    32,
				MaxLength:    32,
				AllowedChars: "abcdef0123456789",
				KnownPrefix:  "xoxp-",
			},
			wantRules: DetectorPrefilterRules{
				MinLength:    32,
				MaxLength:    32,
				AllowedChars: "abcdef0123456789",
				KnownPrefix:  "xoxp-",
			},
			wantFound:      true,
			shouldRegister: true,
		},
		{
			name:         "zero values are valid",
			detectorType: detectorspb.DetectorType_Generic,
			rules: DetectorPrefilterRules{
				MinLength:    0,
				MaxLength:    0,
				AllowedChars: "",
				KnownPrefix:  "",
			},
			wantRules: DetectorPrefilterRules{
				MinLength:    0,
				MaxLength:    0,
				AllowedChars: "",
				KnownPrefix:  "",
			},
			wantFound:      true,
			shouldRegister: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear the map before each test.
			detectorConstraints = map[detectorspb.DetectorType]DetectorPrefilterRules{}

			if tt.shouldRegister {
				RegisterConstraints(tt.detectorType, tt.rules)
			}

			gotRules, gotFound := GetConstraints(tt.detectorType)
			assert.Equal(t, tt.wantRules, gotRules)
			assert.Equal(t, tt.wantFound, gotFound)

			if tt.wantFound {
				assert.Equal(t, tt.wantRules.MinLength, gotRules.MinLength)
				assert.Equal(t, tt.wantRules.MaxLength, gotRules.MaxLength)
				assert.Equal(t, tt.wantRules.AllowedChars, gotRules.AllowedChars)
				assert.Equal(t, tt.wantRules.KnownPrefix, gotRules.KnownPrefix)
			}
		})
	}
}
