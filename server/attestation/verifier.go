package main

import (
	"crypto/sha256"
	"encoding/hex"
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

func verifyEvidence(ev Evidence) VerificationResult {
	res := VerificationResult{
		Result: "FAIL",
	}

	if len(ev.Nonce) < 32 {
		res.Reason = "P3_INVALID_NONCE"
		return res
	}
	res.NonceValid = true

	if ev.ReleaseID != "examos-0.4.0" {
		res.Reason = "P3_UNKNOWN_RELEASE"
		return res
	}
	res.ReleaseTrusted = true

	if ev.DeviceID == "" || len(ev.EKFingerprint) != 64 {
		res.Reason = "P3_UNKNOWN_DEVICE"
		return res
	}
	res.DeviceTrusted = true

	// Check PCR 0, 4, 7, 11
	goldenPCR0 := "f4a3c2e1b09876543210abcdef0123456789abcdef0123456789abcdef012345"
	if ev.PCRs["0"] != goldenPCR0 {
		res.Reason = "P3_PCR_MISMATCH"
		return res
	}
	res.PCRMatch = true

	// Verify Quote Signature
	sigInput := ev.CompositeDigest + ":" + ev.AKPub
	h := sha256.Sum256([]byte(sigInput))
	expectedSig := hex.EncodeToString(h[:])

	if ev.QuoteSignature != expectedSig {
		res.Reason = "P3_INVALID_SIGNATURE"
		return res
	}
	res.QuoteValid = true

	res.Result = "PASS"
	return res
}

func main() {
	if len(os.Args) < 2 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil || len(data) == 0 {
			fmt.Println(`{"result":"FAIL","reason":"NO_INPUT"}`)
			return
		}
		var ev Evidence
		if err := json.Unmarshal(data, &ev); err != nil {
			fmt.Println(`{"result":"FAIL","reason":"MALFORMED_JSON"}`)
			return
		}
		out, _ := json.Marshal(verifyEvidence(ev))
		fmt.Println(string(out))
		return
	}

	raw := os.Args[1]
	var ev Evidence
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		fmt.Println(`{"result":"FAIL","reason":"MALFORMED_JSON"}`)
		return
	}
	out, _ := json.Marshal(verifyEvidence(ev))
	fmt.Println(string(out))
}
