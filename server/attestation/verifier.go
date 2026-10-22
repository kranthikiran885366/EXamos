package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Evidence struct {
	Timestamp       int64             `json:"timestamp"`
	DeviceID        string            `json:"device_id"`
	ReleaseID       string            `json:"release_id"`
	Nonce           string            `json:"nonce"`
	TPMHardware     bool              `json:"tpm_hardware"`
	EKFingerprint   string            `json:"ek_fingerprint"`
	AKPub           string            `json:"ak_pub"`
	QuoteSignature  string            `json:"quote_signature"`
	EventLogHash    string            `json:"event_log_hash"`
	PCRs            map[string]string `json:"pcrs"`
	CompositeDigest string            `json:"composite_digest"`
}

type VerificationResult struct {
	Result         string `json:"result"`
	DeviceTrusted  bool   `json:"deviceTrusted"`
	ReleaseTrusted bool   `json:"releaseTrusted"`
	NonceValid     bool   `json:"nonceValid"`
	QuoteValid     bool   `json:"quoteValid"`
	PCRMatch       bool   `json:"pcrMatch"`
	Reason         string `json:"reason,omitempty"`
}

// The standalone Go verifier is deliberately disabled. It has no authenticated
// trust configuration, enrolled TPM key, release registry, or TPM quote parser.
// Never infer attestation from caller-supplied digests or signature-shaped data.
func verifyEvidence(_ Evidence) VerificationResult {
	return VerificationResult{
		Result: "FAIL",
		Reason: "P3_VERIFIER_DISABLED",
	}
}

func main() {
	var data []byte
	var err error
	if len(os.Args) < 2 {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data = []byte(os.Args[1])
	}
	if err != nil || len(data) == 0 {
		fmt.Println(`{"result":"FAIL","reason":"NO_INPUT"}`)
		return
	}
	var evidence Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		fmt.Println(`{"result":"FAIL","reason":"MALFORMED_JSON"}`)
		return
	}
	out, err := json.Marshal(verifyEvidence(evidence))
	if err != nil {
		fmt.Println(`{"result":"FAIL","reason":"SERIALIZATION_ERROR"}`)
		return
	}
	fmt.Println(string(out))
}
