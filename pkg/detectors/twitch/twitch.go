package twitch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const verifyURL = "https://id.twitch.tv/oauth2/token"

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"twitch"}) + `\b([0-9a-z]{30})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"twitch"}) + `\b([0-9a-z]{30})\b`)
)

// Interface assertions to ensure implementations satisfy required interfaces
var (
	_ detectors.PatternDetector = (*Detector)(nil)
	_ detectors.Verifier        = (*Verifier)(nil)
)

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

// Verifier implements credential verification for Twitch client credentials.
// It attempts to authenticate with the Twitch API using candidate credentials.
type Verifier struct{ client *http.Client }

// NewVerifier creates a new Verifier with the given options
func NewVerifier(client *http.Client) Verifier {
	if client == nil {
		client = defaultClient
	}
	return Verifier{client: client}
}

// Verify checks if the provided Twitch credentials are valid by attempting to obtain
// an OAuth token from the Twitch API.
func (tv Verifier) Verify(ctx context.Context, c detectors.Candidate) (bool, error) {
	resMatch := string(c.Raw)
	resIdMatch := c.ExtraData["IDMatch"]
	return verifyTwitch(ctx, tv.client, resMatch, resIdMatch)
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

func verifyTwitch(ctx context.Context, client *http.Client, resMatch string, resIdMatch string) (bool, error) {
	data := url.Values{}
	data.Set("client_id", resIdMatch)
	data.Set("client_secret", resMatch)
	data.Set("grant_type", "client_credentials")
	encodedData := data.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(encodedData))
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected http response status %d", res.StatusCode)
	}
}
