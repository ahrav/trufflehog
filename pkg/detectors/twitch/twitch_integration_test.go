//go:build detectors
// +build detectors

package twitch

import (
	"context"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestTwitchVerifier_Verify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors3")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("TWITCH")
	id := testSecrets.MustGetField("TWITCH_ID")
	inactiveSecret := testSecrets.MustGetField("TWITCH_INACTIVE")

	type args struct {
		ctx       context.Context
		candidate detectors.Candidate
	}
	tests := []struct {
		name                string
		v                   detectors.Verifier
		args                args
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name: "verified",
			v:    NewVerifier(nil),
			args: args{
				ctx: context.Background(),
				candidate: detectors.Candidate{
					Raw: []byte(secret),
					ExtraData: map[string]string{
						"IDMatch": id,
					},
				},
			},
			wantVerified:        true,
			wantVerificationErr: false,
		},
		{
			name: "unverified with timeout",
			v:    NewVerifier(common.SaneHttpClientTimeOut(1 * time.Microsecond)),
			args: args{
				ctx: context.Background(),
				candidate: detectors.Candidate{
					Raw: []byte(secret),
					ExtraData: map[string]string{
						"IDMatch": id,
					},
				},
			},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name: "unverified with bad status",
			v:    NewVerifier(common.ConstantResponseHttpClient(404, "")),
			args: args{
				ctx: context.Background(),
				candidate: detectors.Candidate{
					Raw: []byte(secret),
					ExtraData: map[string]string{
						"IDMatch": id,
					},
				},
			},
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name: "unverified with inactive secret",
			v:    NewVerifier(nil),
			args: args{
				ctx: context.Background(),
				candidate: detectors.Candidate{
					Raw: []byte(inactiveSecret),
					ExtraData: map[string]string{
						"IDMatch": id,
					},
				},
			},
			wantVerified:        false,
			wantVerificationErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified, err := tt.v.Verify(tt.args.ctx, tt.args.candidate)
			if (err != nil) != tt.wantVerificationErr {
				t.Errorf("TwitchVerifier.Verify() error = %v, wantVerificationErr %v", err, tt.wantVerificationErr)
				return
			}
			if verified != tt.wantVerified {
				t.Errorf("TwitchVerifier.Verify() verified = %v, want %v", verified, tt.wantVerified)
			}
		})
	}
}

func BenchmarkFindCandidates(benchmark *testing.B) {
	ctx := context.Background()
	s := Detector{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FindCandidates(ctx, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
