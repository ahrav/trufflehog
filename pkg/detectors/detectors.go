package detectors

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"unicode"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/registry"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Detector defines an interface for scanning for and verifying secrets.
type Detector interface {
	// FromData will scan bytes for results, and optionally verify them.
	FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
	// Keywords are used for efficiently pre-filtering chunks using substring operations.
	// Use unique identifiers that are part of the secret if you can, or the provider name.
	Keywords() []string
	// Type returns the DetectorType number from detectors.proto for the given detector.
	Type() detectorspb.DetectorType
	// Description returns a description for the result being detected
	Description() string
}

// Candidate represents a potential secret that has been detected but not yet verified.
// It contains both the raw secret data and metadata about the detection.
type Candidate struct {
	Raw       []byte
	RawV2     []byte
	Redacted  string
	ExtraData map[string]string
}

// toResult converts a Candidate into a Result by adding the detector type.
// This is used internally when a detector needs to return its findings.
func (c Candidate) toResult(dt detectorspb.DetectorType) Result {
	return Result{
		DetectorType: dt,
		Raw:          c.Raw,
		RawV2:        c.RawV2,
		Redacted:     c.Redacted,
		ExtraData:    c.ExtraData,
	}
}

// PatternDetector defines the interface for secret detection logic.
// Implementations of this interface handle the pattern matching and extraction
// of candidates.
type PatternDetector interface {
	// FindCandidates scans the input data and returns any candidates found.
	FindCandidates(ctx context.Context, data []byte) ([]Candidate, error)
	// Type returns the specific type of detector (e.g. AWS, GitHub, etc).
	Type() detectorspb.DetectorType
	// Description returns human-readable information about what this detector looks for.
	Description() string
}

// Verifier defines the interface for secret verification logic.
// Implementations handle validating whether a detected secret is valid
// by making API calls or other verification steps. (eg db connection)
type Verifier interface {
	// Verify checks if a candidate secret is valid and currently active.
	// Returns true if the secret is verified as valid.
	Verify(ctx context.Context, candidate Candidate) (bool, error)
}

// PatternBasedDetector is an adapter that implements the old Detector interface.
// It is used to implement new detectors while keeping the old interface for backwards compatibility.
// It maintains backward compatibility by using the old interface's methods, but delegates the actual
// detection logic to the patternDetector and verifier.
//
// This is a temporary adapter to help with the transition to the new detector interface.
// It will be removed once all detectors have been updated to the new interface.
type PatternBasedDetector struct {
	Detector    PatternDetector
	Verifier    Verifier
	KeywordList []string
}

// Keywords returns the keywords for the detector.
func (p PatternBasedDetector) Keywords() []string { return p.KeywordList }

// Type returns the DetectorType number from detectors.proto for the given detector.
func (p PatternBasedDetector) Type() detectorspb.DetectorType { return p.Detector.Type() }

// Description returns a description for the result being detected
func (p PatternBasedDetector) Description() string { return p.Detector.Description() }

// FromData will scan bytes for results, and optionally verify them.
// This is the old Detector interface's FromData method.
func (p PatternBasedDetector) FromData(ctx context.Context, verify bool, data []byte) ([]Result, error) {
	criteria, ok := registry.GetConstraints(p.Type())
	if ok && !criteria.Matches(data) {
		return nil, nil
	}

	var finalResults []Result
	detectedCandidates, err := p.Detector.FindCandidates(ctx, data)
	if err != nil {
		return nil, err
	}

	for _, c := range detectedCandidates {
		res := c.toResult(p.Detector.Type())
		if verify {
			ok, verr := p.Verifier.Verify(ctx, c)
			if verr != nil {
				res.SetVerificationError(verr, string(c.Raw))
			}
			res.Verified = ok
			if ok {
				finalResults = append(finalResults, res)
			}
		} else {
			// Without verification, just return what we found.
			finalResults = append(finalResults, res)
		}
	}

	return finalResults, nil
}

// CustomResultsCleaner is an optional interface that a detector can implement to customize how its generated results
// are "cleaned," which is defined as removing superfluous results from those found in a given chunk. The default
// implementation of this logic removes all unverified results if there are any verified results, and all unverified
// results except for one otherwise, but this interface allows a detector to specify different logic. (This logic must
// be implemented outside results generation because there are circumstances under which the engine should not execute
// it.)
type CustomResultsCleaner interface {
	// CleanResults removes "superfluous" results from a result set (where the definition of "superfluous" is detector-
	// specific).
	CleanResults(results []Result) []Result
	// ShouldCleanResultsIrrespectiveOfConfiguration allows a custom cleaner to instruct the engine to ignore
	// user-provided configuration that controls whether results are cleaned. (User-provided configuration is not the
	// only factor that determines whether the engine runs cleaning logic.)
	ShouldCleanResultsIrrespectiveOfConfiguration() bool
}

// Versioner is an optional interface that a detector can implement to
// differentiate instances of the same detector type.
type Versioner interface {
	Version() int
}

// MaxSecretSizeProvider is an optional interface that a detector can implement to
// provide a custom max size for the secret it finds.
type MaxSecretSizeProvider interface {
	MaxSecretSize() int64
}

// StartOffsetProvider is an optional interface that a detector can implement to
// provide a custom start offset for the secret it finds.
type StartOffsetProvider interface {
	StartOffset() int64
}

// MultiPartCredentialProvider is an optional interface that a detector can implement
// to indicate its compatibility with multi-part credentials and provide the maximum
// secret size for the credential it finds.
type MultiPartCredentialProvider interface {
	// MaxCredentialSpan returns the maximum span or range of characters that the
	// detector should consider when searching for a multi-part credential.
	MaxCredentialSpan() int64
}

// EndpointCustomizer is an optional interface that a detector can implement to
// support verifying against user-supplied endpoints.
type EndpointCustomizer interface {
	SetConfiguredEndpoints(...string) error
	SetCloudEndpoint(string)
	UseCloudEndpoint(bool)
	UseFoundEndpoints(bool)
}

type CloudProvider interface {
	CloudEndpoint() string
}

type Result struct {
	// DetectorType is the type of Detector.
	DetectorType detectorspb.DetectorType
	// DetectorName is the name of the Detector. Used for custom detectors.
	DetectorName string
	Verified     bool
	// Raw contains the raw secret identifier data. Prefer IDs over secrets since it is used for deduping after hashing.
	Raw []byte
	// RawV2 contains the raw secret identifier that is a combination of both the ID and the secret.
	// This is used for secrets that are multi part and could have the same ID. Ex: AWS credentials
	RawV2 []byte
	// Redacted contains the redacted version of the raw secret identification data for display purposes.
	// A secret ID should be used if available.
	Redacted       string
	ExtraData      map[string]string
	StructuredData *detectorspb.StructuredData

	// This field should only be populated if the verification process itself failed in a way that provides no
	// information about the verification status of the candidate secret, such as if the verification request timed out.
	verificationError error

	// AnalysisInfo should be set with information required for credential
	// analysis to run. The keys of the map are analyzer specific and
	// should match what is expected in the corresponding analyzer.
	AnalysisInfo map[string]string
}

// SetVerificationError is the only way to set a verification error. Any sensitive values should be passed-in as secrets to be redacted.
func (r *Result) SetVerificationError(err error, secrets ...string) {
	if err != nil {
		r.verificationError = redactSecrets(err, secrets...)
	}
}

// Public accessors for the fields could also be provided if needed.
func (r *Result) VerificationError() error {
	return r.verificationError
}

// redactSecrets replaces all instances of the given secrets with [REDACTED] in the error message.
func redactSecrets(err error, secrets ...string) error {
	lastErr := unwrapToLast(err)
	errStr := lastErr.Error()
	for _, secret := range secrets {
		errStr = strings.Replace(errStr, secret, "[REDACTED]", -1)
	}
	return errors.New(errStr)
}

// unwrapToLast returns the last error in the chain of errors.
// This is added to exclude non-essential details (like URLs) for brevity and security.
// Also helps us optimize performance in redaction and enhance log clarity.
func unwrapToLast(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			// We've reached the last error in the chain
			return err
		}
		err = unwrapped
	}
}

type ResultWithMetadata struct {
	// IsWordlistFalsePositive indicates whether this secret was flagged as a false positive based on a wordlist check
	IsWordlistFalsePositive bool
	// SourceMetadata contains source-specific contextual information.
	SourceMetadata *source_metadatapb.MetaData
	// SourceID is the ID of the source that the API uses to map secrets to specific sources.
	SourceID sources.SourceID
	// JobID is the ID of the job that the API uses to map secrets to specific jobs.
	JobID sources.JobID
	// SecretID is the ID of the secret, if it exists.
	// Only secrets that are being reverified will have a SecretID.
	SecretID int64
	// SourceType is the type of Source.
	SourceType sourcespb.SourceType
	// SourceName is the name of the Source.
	SourceName string
	Result
	// Data from the sources.Chunk which this result was emitted for
	Data []byte
	// DetectorDescription is the description of the Detector.
	DetectorDescription string
	// DecoderType is the type of decoder that was used to generate this result's data.
	DecoderType detectorspb.DecoderType
}

// CopyMetadata returns a detector result with included metadata from the source chunk.
func CopyMetadata(chunk *sources.Chunk, result Result) ResultWithMetadata {
	return ResultWithMetadata{
		SourceMetadata: chunk.SourceMetadata,
		SourceID:       chunk.SourceID,
		JobID:          chunk.JobID,
		SecretID:       chunk.SecretID,
		SourceType:     chunk.SourceType,
		SourceName:     chunk.SourceName,
		Result:         result,
		Data:           chunk.Data,
	}
}

// CleanResults returns all verified secrets, and if there are no verified secrets,
// just one unverified secret if there are any.
func CleanResults(results []Result) []Result {
	if len(results) == 0 {
		return results
	}

	var cleaned = make(map[string]Result, 0)

	for _, s := range results {
		if s.Verified {
			cleaned[s.Redacted] = s
		}
	}

	if len(cleaned) == 0 {
		return results[:1]
	}

	results = results[:0]
	for _, r := range cleaned {
		results = append(results, r)
	}

	return results
}

// PrefixRegex ensures that at least one of the given keywords is within
// 40 characters of the capturing group that follows.
// This can help prevent false positives.
func PrefixRegex(keywords []string) string {
	pre := `(?i:`
	middle := strings.Join(keywords, "|")
	post := `)(?:.|[\n\r]){0,40}?`
	return pre + middle + post
}

// KeyIsRandom is a Low cost check to make sure that 'keys' include a number to reduce FPs.
// Golang doesn't support regex lookaheads, so must be done in separate calls.
// TODO improve checks. Shannon entropy did not work well.
func KeyIsRandom(key string) bool {
	for _, ch := range key {
		if unicode.IsDigit(ch) {
			return true
		}
	}

	return false
}

func MustGetBenchmarkData() map[string][]byte {
	sizes := map[string]int{
		"xsmall":  10,          // 10 bytes
		"small":   100,         // 100 bytes
		"medium":  1024,        // 1KB
		"large":   10 * 1024,   // 10KB
		"xlarge":  100 * 1024,  // 100KB
		"xxlarge": 1024 * 1024, // 1MB
	}
	data := make(map[string][]byte)

	for key, size := range sizes {
		// Generating a byte slice of a specific size with random data.
		content := make([]byte, size)
		for i := 0; i < size; i++ {
			randomByte, err := rand.Int(rand.Reader, big.NewInt(256))
			if err != nil {
				panic(err)
			}
			content[i] = byte(randomByte.Int64())
		}
		data[key] = content
	}

	return data
}

func RedactURL(u url.URL) string {
	u.User = url.UserPassword(u.User.Username(), "********")
	return strings.TrimSpace(strings.Replace(u.String(), "%2A", "*", -1))
}

func ParseURLAndStripPathAndParams(u string) (*url.URL, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	parsedURL.Path = ""
	parsedURL.RawQuery = ""
	return parsedURL, nil
}
