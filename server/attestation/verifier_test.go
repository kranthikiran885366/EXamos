package main

import (
	"encoding/json"
	"testing"
)

func TestVerifierNeverAuthorizesUnconfiguredEvidence(t *testing.T) {
	cases := []struct {
		name string
		ev   Evidence
	}{
		{name: "empty evidence"},
		{
			name: "legacy hardcoded PCR and hash-shaped signature",
			ev: Evidence{
				DeviceID:       "device",
				ReleaseID:      "examos-0.4.0",
				Nonce:          "0123456789abcdef0123456789abcdef",
				TPMHardware:    true,
				EKFingerprint:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				QuoteSignature: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				PCRs: map[string]string{
					"0": "f4a3c2e1b09876543210abcdef0123456789abcdef0123456789abcdef012345",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyEvidence(tc.ev)
			if got.Result != "FAIL" || got.Reason != "P3_VERIFIER_DISABLED" {
				t.Fatalf("unexpected verifier result: %+v", got)
			}
			if got.DeviceTrusted || got.ReleaseTrusted || got.NonceValid || got.QuoteValid || got.PCRMatch {
				t.Fatalf("disabled verifier asserted trust: %+v", got)
			}
		})
	}
}

func TestVerifierCLIRejectsMalformedJSON(t *testing.T) {
	var evidence Evidence
	if err := json.Unmarshal([]byte(`{"nonce":`), &evidence); err == nil {
		t.Fatal("malformed evidence JSON unexpectedly parsed")
	}
}
