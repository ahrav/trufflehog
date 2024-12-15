package detectors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPVerifier(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		config         HTTPVerifierConfig
		wantValid      bool
		wantErr        bool
	}{
		{
			name: "valid credentials - 200 response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			config:    HTTPVerifierConfig{Method: http.MethodGet},
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "valid credentials - 201 response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			},
			config:    HTTPVerifierConfig{Method: http.MethodPost},
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "invalid credentials - 401 response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			config:    HTTPVerifierConfig{Method: http.MethodGet},
			wantValid: false,
			wantErr:   false,
		},
		{
			name: "invalid credentials - 403 response",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			config:    HTTPVerifierConfig{Method: http.MethodGet},
			wantValid: false,
			wantErr:   false,
		},
		{
			name: "unexpected status code - error",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			config:    HTTPVerifierConfig{Method: http.MethodGet},
			wantValid: false,
			wantErr:   true,
		},
		{
			name: "custom headers are sent",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Custom") != "test" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			config: HTTPVerifierConfig{
				Method: http.MethodGet,
				Headers: map[string]string{
					"X-Custom": "test",
				},
			},
			wantValid: true,
			wantErr:   false,
		},
		{
			name: "custom response validator",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Custom-Valid", "true")
				w.WriteHeader(http.StatusTeapot) // unusual status that would normally error
			},
			config: HTTPVerifierConfig{
				ValidateResponse: func(resp *http.Response) (bool, error) {
					return resp.Header.Get("X-Custom-Valid") == "true", nil
				},
			},
			wantValid: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.serverResponse))
			defer server.Close()

			tt.config.Endpoint = server.URL

			v := NewHTTPVerifier(tt.config)

			valid, err := v.Verify(context.Background(), Candidate{})

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantValid, valid)
		})
	}
}

func TestHTTPVerifierDefaultMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewHTTPVerifier(HTTPVerifierConfig{
		Endpoint: server.URL,
	})

	valid, err := v.Verify(context.Background(), Candidate{})
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestHTTPVerifierContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow response.
		select {
		case <-r.Context().Done():
			return
		}
	}))
	defer server.Close()

	v := NewHTTPVerifier(HTTPVerifierConfig{
		Endpoint: server.URL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := v.Verify(ctx, Candidate{})
	assert.Error(t, err)
}

func TestHTTPVerifierCustomPrepareRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for custom query parameter.
		if r.URL.Query().Get("key") != "value" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Check for request body.
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"test":"data"}` {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Check for custom method.
		if r.Method != http.MethodPatch {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewHTTPVerifier(HTTPVerifierConfig{
		Endpoint: server.URL,
		PrepareRequest: func(ctx context.Context, c Candidate) (*http.Request, error) {
			body := strings.NewReader(`{"test":"data"}`)
			req, err := http.NewRequestWithContext(ctx, http.MethodPatch, server.URL, body)
			if err != nil {
				return nil, err
			}
			q := req.URL.Query()
			q.Add("key", "value")
			req.URL.RawQuery = q.Encode()
			return req, nil
		},
	})

	valid, err := v.Verify(context.Background(), Candidate{})
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestHTTPVerifierTimeout(t *testing.T) {
	const defaultTimeout = 5 * time.Millisecond
	// Create a server that delays before responding.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(defaultTimeout) // Artificial delay
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := NewHTTPVerifier(HTTPVerifierConfig{Endpoint: server.URL})

	// Test with a timeout less than the server delay.
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout/2)
	defer cancel()

	_, err := v.Verify(ctx, Candidate{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")

	// Test with a timeout greater than the server delay.
	ctx, cancel = context.WithTimeout(context.Background(), defaultTimeout*2)
	defer cancel()

	valid, err := v.Verify(ctx, Candidate{})
	assert.NoError(t, err)
	assert.True(t, valid)
}
