package voiceflow

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(VF\.(?:(?:DM|WS)\.)?[a-fA-F0-9]{24}\.[a-zA-Z0-9]{16})\b`)
)

var _ detectors.PatternDetector = (*Detector)(nil)

// Detector extracts Voiceflow API keys from raw data.
type Detector struct {
	keyPat *regexp.Regexp
}

// FindCandidates searches for Voiceflow credentials in the provided data.
func (d Detector) FindCandidates(ctx context.Context, data []byte) ([]detectors.Candidate, error) {
	dataStr := string(data)
	matches := d.keyPat.FindAllStringSubmatch(dataStr, -1)

	var candidates []detectors.Candidate
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		candidates = append(candidates, detectors.Candidate{
			Raw: []byte(strings.TrimSpace(match[1])),
		})
	}

	return candidates, nil
}

// Type returns the DetectorType for Voiceflow credentials.
func (d Detector) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Voiceflow
}

// Description returns a human-readable description of the detector's purpose.
func (d Detector) Description() string {
	return "Voiceflow is an AI service designed to transact with customers. API keys may be used to access customer data."
}

// NewVerifier creates a new Verifier with the given options
func NewVerifier(client *http.Client) detectors.Verifier {
	if client == nil {
		client = defaultClient
	}

	const verifyURL = "https://general-runtime.voiceflow.com/knowledge-base/query"
	config := detectors.HTTPVerifierConfig{
		Endpoint: verifyURL,
		Method:   http.MethodPost,
		Client:   client,
		PrepareRequest: func(ctx context.Context, c detectors.Candidate) (*http.Request, error) {
			payload := []byte(`{"question": "why is the sky blue?"}`)
			req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, bytes.NewBuffer(payload))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", string(c.Raw))
			req.Header.Set("Content-Type", "application/json")
			return req, nil
		},
		ValidateResponse: func(res *http.Response) (bool, error) {
			if res.StatusCode == http.StatusOK {
				return true, nil
			} else if res.StatusCode == http.StatusUnauthorized {
				return false, nil
			}

			var buf bytes.Buffer
			var bodyString string
			_, err := io.Copy(&buf, res.Body)
			if err == nil {
				bodyString = buf.String()
			}
			return false, fmt.Errorf("unexpected HTTP response [status=%d, body=%s]", res.StatusCode, bodyString)
		},
	}

	return detectors.NewHTTPVerifier(config)
}

// NewDetector creates and returns a new Voiceflow detector
func NewDetector() detectors.Detector {
	patternDet := Detector{keyPat: keyPat}
	verifier := NewVerifier(defaultClient)

	detectors.RegisterDetectorWithOptions(
		detectors.DetectorRegistrationOptions{
			DetectorType: detectorspb.DetectorType_Voiceflow,
			PrefilterConfig: detectors.DetectorPrefilterConfig{
				MinLength:    40, // VF.DM.123456789012345678901234.1234567890123456
				AllowedChars: common.AlphaNumericChars(),
			},
			PatternDetector: patternDet,
			Verifier:        verifier,
			Keywords:        []string{"vf", "dm"},
		},
	)

	def, err := detectors.GetDefaultDetectorDefinition(detectorspb.DetectorType_Voiceflow)
	if err != nil {
		panic(err)
	}

	return detectors.PatternBasedDetector{
		Detector:          patternDet,
		Verifier:          verifier,
		KeywordList:       []string{"vf", "dm"},
		PrefilterCriteria: def.PrefilterCriteria,
	}
}
