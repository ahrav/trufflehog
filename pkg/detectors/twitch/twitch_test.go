package twitch

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKey   = "k0lj2mwl8n3ztmrivlpbc7obk914sj"
	invalidKey = "k0lj2mwl8n3ztmr?vlpbc7obk914sj"
	validId    = "kn64qw9jt39bhni04h2k5jc7ebefyn"
	invalidId  = "kn64qw9jt39bhni?4h2k5jc7ebefyn"
	keyword    = "twitch"
)

func TestTwitch_FindCandidates(t *testing.T) {
	d := NewDetector()

	detector := d.(detectors.PatternBasedDetector).Detector.(Detector)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword twitch",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validKey, keyword, validId),
			want:  []string{validKey, validId, validId, validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidKey, keyword, invalidId),
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			candidates, err := detector.FindCandidates(context.Background(), []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(candidates) != len(test.want) {
				if len(candidates) == 0 {
					t.Errorf("did not receive candidates")
				} else {
					t.Errorf("expected %d candidates, only received %d", len(test.want), len(candidates))
				}
				return
			}

			actual := make(map[string]struct{}, len(candidates))
			for _, c := range candidates {
				actual[string(c.Raw)] = struct{}{}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
