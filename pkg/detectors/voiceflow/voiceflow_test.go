package voiceflow

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestVoiceflow_FindCandidates(t *testing.T) {
	d := NewDetector()

	detector := d.(detectors.PatternBasedDetector).Detector.(Detector)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - from funDAOmental/endlessquest",
			input: `// z0MG IT'S NOT A SECRET (but we'll delete it)
const API_KEY = "VF.DM.6469b4e5909a470007b96250.k4ip0SMy84jWlCsF"; // it should look like this: VF.DM.XXXXXXX.XXXXXX... keep this a secret!`,
			want: []string{"VF.DM.6469b4e5909a470007b96250.k4ip0SMy84jWlCsF"},
		},
		{
			name: "valid pattern - from sherifButt/ll-site",
			input: `  const runtime = useRuntime({
    verify: { authorization: 'VF.DM.652da078cde70b0008e1c5df.zsIo23VTxNXKfb9f' },
    session: { userID: 'user_123' },
  });`,
			want: []string{"VF.DM.652da078cde70b0008e1c5df.zsIo23VTxNXKfb9f"},
		},
		{
			name: "valid pattern - from the-vv/Voiceflow-chatbot",
			input: `    this.http.delete('https://general-runtime.voiceflow.com/state/user/TEST_USER', {
      headers: {
        Authorization: "VF.DM.652ecc210267ec00078fc726.ZFPdEwvU0d1jiIMq"
      }
    })`,
			want: []string{"VF.DM.652ecc210267ec00078fc726.ZFPdEwvU0d1jiIMq"},
		},
		{
			name: "valid pattern - from legionX7/Graduation-Project-API",
			input: `
API_KEY = 'VF.DM.646388eb1419c80007bbbaa4.XHOqETFO3cvTxlGl'
VERSION_ID = '646bc'`,
			want: []string{"VF.DM.646388eb1419c80007bbbaa4.XHOqETFO3cvTxlGl"},
		},
		{
			name: "valid pattern - from voiceflow/general-runtime",
			input: ` it('extracts ID from a Dialog Manager API key', () => {
      // eslint-disable-next-line no-secrets/no-secrets
      const key = 'VF.DM.628d5d92faf688001bda7907.dmC8KKO1oX8JO5ai';`,
			want: []string{"VF.DM.628d5d92faf688001bda7907.dmC8KKO1oX8JO5ai"},
		},
		{
			name:  "valid pattern - legacy workspace key",
			input: `      const key = 'VF.WS.62bcb0cca5184300066f5ac7.egnKyyzZksiS5iGa';`,
			want:  []string{"VF.WS.62bcb0cca5184300066f5ac7.egnKyyzZksiS5iGa"},
		},
		{
			name:  "valid pattern - legacy key",
			input: `      const key = 'VF.62bcb0cca5184300066f5ac7.dmC8KKO1oX8JO5az';`,
			want:  []string{"VF.62bcb0cca5184300066f5ac7.dmC8KKO1oX8JO5az"},
		},
		{
			name:  "invalid pattern - example key",
			input: "Now, paste it in your .env file for the **VF_PROJECT_API** variable<br>\n```VF_PROJECT_API='VF.DM.62xxxxxxxxxxxxxxxxxxxxxxx'```",
			want:  []string{},
		},
		{
			name:  "invalid pattern - placeholder",
			input: `const API_KEY: &str = "YOUR_API_KEY_HERE"; // it should look like this: VF.DM.XXXXXXX.XXXXXX... keep this a secret!`,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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
