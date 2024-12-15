package twitch

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"twitch"}) + `\b([0-9a-z]{30})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"twitch"}) + `\b([0-9a-z]{30})\b`)
)

// Interface assertions to ensure implementations satisfy required interfaces
var _ detectors.PatternDetector = (*Detector)(nil)

// Detector extracts Twitch client ID and secret token pairs from raw data.
// It implements the PatternDetector interface to find candidate credentials.
type Detector struct {
	detectors.DefaultMultiPartCredentialProvider

	// keyPat matches Twitch client secrets
	// idPat matches Twitch client IDs
	keyPat, idPat *regexp.Regexp
}

// FindCandidates searches for Twitch credential pairs in the provided data.
// It looks for client IDs and secrets that match Twitch's format and returns
// them as candidates for verification. The client secret is stored in Raw and
// the client ID is stored in ExtraData["IDMatch"].
func (tp Detector) FindCandidates(ctx context.Context, data []byte) ([]detectors.Candidate, error) {
	dataStr := string(data)
	matches := tp.keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := tp.idPat.FindAllStringSubmatch(dataStr, -1)

	var candidates []detectors.Candidate
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idMatch[1])

			candidates = append(candidates, detectors.Candidate{
				Raw: []byte(resMatch),
				ExtraData: map[string]string{
					"IDMatch": resIdMatch,
				},
			})
		}
	}
	return candidates, nil
}

// Type returns the DetectorType for Twitch credentials.
func (tp Detector) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twitch
}

// Description returns a human-readable description of the detector's purpose.
func (tp Detector) Description() string { return "Detects Twitch tokens" }

// NewVerifier creates a new Verifier with the given options
func NewVerifier(client *http.Client) detectors.Verifier {
	if client == nil {
		client = defaultClient
	}

	const verifyURL = "https://id.twitch.tv/oauth2/token"
	config := detectors.HTTPVerifierConfig{
		Endpoint: verifyURL,
		Method:   http.MethodPost,
		Client:   client,
		PrepareRequest: func(ctx context.Context, c detectors.Candidate) (*http.Request, error) {
			data := url.Values{}
			data.Set("client_id", c.ExtraData["IDMatch"])
			data.Set("client_secret", string(c.Raw))
			data.Set("grant_type", "client_credentials")

			return http.NewRequestWithContext(ctx, "POST", verifyURL,
				strings.NewReader(data.Encode()))
		},
	}

	return detectors.NewHTTPVerifier(config)
}

// NewDetector creates and returns a new Twitch detector that can find and verify
// Twitch client credentials. It combines pattern detection and verification capabilities
// into a single detector instance.
func NewDetector() detectors.Detector {
	patternDet := Detector{keyPat: keyPat, idPat: idPat}
	verifier := NewVerifier(defaultClient)

	return detectors.PatternBasedDetector{
		Detector:    patternDet,
		Verifier:    verifier,
		KeywordList: []string{"twitch"},
	}
}
