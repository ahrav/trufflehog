package detectors

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// HTTPVerifier provides a reusable way to verify credentials by making HTTP requests.
// It handles common verification patterns like checking status codes and allows
// customization of request preparation and response validation.
type HTTPVerifier struct {
	endpoint         string
	method           string
	headers          map[string]string
	client           *http.Client
	prepareRequest   func(ctx context.Context, c Candidate) (*http.Request, error)
	validateResponse func(resp *http.Response) (bool, error)
}

// HTTPVerifierConfig configures how the HTTPVerifier makes requests and validates responses.
// At minimum, an Endpoint must be provided. The other fields allow customizing the
// verification behavior, from simple header tweaks to complete request/response handling.
type HTTPVerifierConfig struct {
	// Endpoint is the URL that credentials will be verified against.
	// This is required.
	Endpoint string

	// Method specifies the HTTP method to use, defaults to "POST" if not set.
	Method string
	// Headers are added to each request unless PrepareRequest is used.
	Headers map[string]string
	// Client is the HTTP client to use for requests.
	Client *http.Client

	// PrepareRequest allows full customization of the HTTP request before sending.
	// If this is not provided, a simple request with no body is created.
	// To include credentials (e.g., via headers, query params, or a request body),
	// ensure they are set here.
	// When PrepareRequest is set, Method and Headers are ignored.
	PrepareRequest func(ctx context.Context, c Candidate) (*http.Request, error)

	// ValidateResponse determines if a response indicates valid credentials.
	// When not set, DefaultResponseValidator is used.
	ValidateResponse func(resp *http.Response) (bool, error)
}

// NewHTTPVerifier creates a new HTTPVerifier with the given configuration.
// It initializes the HTTP client and sets up the default method to "POST".
func NewHTTPVerifier(config HTTPVerifierConfig) Verifier {
	if config.Method == "" {
		config.Method = http.MethodPost
	}
	if config.Client == nil {
		config.Client = common.SaneHttpClient()
	}

	if config.ValidateResponse == nil {
		config.ValidateResponse = DefaultResponseValidator
	}

	return &HTTPVerifier{
		endpoint:         config.Endpoint,
		method:           config.Method,
		headers:          config.Headers,
		client:           config.Client,
		prepareRequest:   config.PrepareRequest,
		validateResponse: config.ValidateResponse,
	}
}

// DefaultResponseValidator provides standard HTTP response validation logic:
// 200/201 indicates valid credentials, 401/403 indicates invalid credentials,
// and other status codes are treated as errors.
func DefaultResponseValidator(resp *http.Response) (bool, error) {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// Verify implements the Verifier interface by making an HTTP request with the candidate
// credentials and validating the response.
func (v *HTTPVerifier) Verify(ctx context.Context, c Candidate) (bool, error) {
	var req *http.Request
	var err error

	if v.prepareRequest != nil {
		req, err = v.prepareRequest(ctx, c)
	} else {
		req, err = http.NewRequestWithContext(ctx, v.method, v.endpoint, nil)
		if err != nil {
			return false, err
		}

		for k, val := range v.headers {
			req.Header.Set(k, val)
		}
	}

	if err != nil {
		return false, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return v.validateResponse(resp)
}
