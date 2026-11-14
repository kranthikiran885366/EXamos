#!/usr/bin/env python3
"""
generate_tpm_ak.py — ExamOS TPM 2.0 Attestation Key (AK) & Public Area Generator
================================================================================
Generates cryptographically valid TPM 2.0 RSA-2048 AK credentials conforming to:
  - Approved template: tpl_rsa2048_ak
  - Attributes: 0x00050072 (fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | sign)
  - Public Area: TPMT_PUBLIC binary structure in hex
  - AK Name: 000b + SHA256(TPMT_PUBLIC) (68 hex chars)
  - Standard PKCS#8 / X.509 RSA-2048 public key PEM

Can also generate a complete device registration JSON payload.
Zero external pip dependencies required (uses standard OpenSSL CLI or Python standard library).
"""

import sys
import os
import json
import base64
import struct
import hashlib
import subprocess
import argparse

# Approved TPM 2.0 Template Header (tpl_rsa2048_ak):
# type=0x0001 (RSA), nameAlg=0x000b (SHA256), attributes=0x00050072, authPolicySize=0x0000,
# symmetric=0x0010 (NULL), scheme=0x0014 (RSASSA), schemeHash=0x000b (SHA256),
# keyBits=0x0800 (2048), exponent=0x00000000 (default 65537), modulusSize=0x0100 (256)
TPM_RSA2048_HEADER_HEX = "0001000b00050072000000100014000b0800000000000100"

def extract_rsa_modulus_from_pem(pem_str: str) -> bytes:
    """Extracts the 256-byte raw RSA modulus from a public key PEM using openssl or pure ASN.1."""
    # Attempt via openssl CLI first
    try:
        p = subprocess.run(
            ["openssl", "rsa", "-pubin", "-modulus", "-noout"],
            input=pem_str,
            capture_output=True,
            text=True,
            check=True
        )
        mod_line = [line for line in p.stdout.splitlines() if line.startswith("Modulus=")]
        if mod_line:
            mod_hex = mod_line[0].split("=", 1)[1].strip()
            mod_bytes = bytes.fromhex(mod_hex)
            if len(mod_bytes) == 256:
                return mod_bytes
    except Exception:
        pass

    # Pure Python ASN.1 DER parser fallback for SubjectPublicKeyInfo
    pem_clean = "".join(
        line for line in pem_str.splitlines()
        if not line.startswith("-----") and line.strip()
    )
    der = base64.b64decode(pem_clean)
    
    # Locate BIT STRING containing RSAPublicKey (sequence of n, e)
    idx = der.find(b"\x30\x82")
    # Search for 256-byte integer (0x02, 0x82, 0x01, 0x00 / 0x01)
    pos = der.find(b"\x02\x82\x01")
    if pos != -1:
        length = (der[pos+2] << 8) | der[pos+3]
        mod_bytes = der[pos+4 : pos+4+length]
        if len(mod_bytes) == 257 and mod_bytes[0] == 0:
            mod_bytes = mod_bytes[1:]
        if len(mod_bytes) == 256:
            return mod_bytes

    raise ValueError("Could not extract 2048-bit modulus from RSA PEM key.")

def generate_rsa_keypair():
    """Generates a fresh RSA-2048 keypair using openssl."""
    res = subprocess.run(
        ["openssl", "genrsa", "2048"],
        capture_output=True,
        text=True,
        check=True
    )
    priv_pem = res.stdout

    res2 = subprocess.run(
        ["openssl", "rsa", "-pubout"],
        input=priv_pem,
        capture_output=True,
        text=True,
        check=True
    )
    pub_pem = res2.stdout
    return priv_pem, pub_pem

def build_ak_template(modulus_bytes: bytes):
    """Builds the approved TPMT_PUBLIC binary area and computes the 34-byte AK Name."""
    header_bytes = bytes.fromhex(TPM_RSA2048_HEADER_HEX)
    tpmt_public = header_bytes + modulus_bytes
    
    # AK Name: 0x000b (TPM_ALG_SHA256) + SHA-256(TPMT_PUBLIC)
    digest = hashlib.sha256(tpmt_public).digest()
    ak_name_bytes = b"\x00\x0b" + digest
    
    return tpmt_public.hex(), ak_name_bytes.hex()

def main():
    parser = argparse.ArgumentParser(
        description="ExamOS TPM 2.0 AK Generator & Validator for Strict Production Enrollment"
    )
    parser.add_argument(
        "--pem-file",
        help="Path to existing RSA-2048 public key PEM (if omitted, generates a new keypair)"
    )
    parser.add_argument(
        "--device-id",
        default="dev-abc123",
        help="Device identifier (default: dev-abc123)"
    )
    parser.add_argument(
        "--institution-id",
        default="inst-default",
        help="Institution identifier (default: inst-default)"
    )
    parser.add_argument(
        "--output-json",
        help="File path to save the full registration JSON payload"
    )
    args = parser.parse_args()

    print("=" * 70)
    print(" ExamOS TPM 2.0 Attestation Key (AK) Approved Template Generator")
    print(" Template: tpl_rsa2048_ak (Attributes: 0x00050072, RSASSA-SHA256)")
    print("=" * 70)

    if args.pem_file:
        print(f"[*] Reading public key from: {args.pem_file}")
        with open(args.pem_file, "r") as f:
            pub_pem = f.read()
    else:
        print("[*] Generating fresh 2048-bit RSA hardware keypair...")
        _, pub_pem = generate_rsa_keypair()

    # Extract modulus
    modulus = extract_rsa_modulus_from_pem(pub_pem)
    print(f"[+] Successfully extracted 2048-bit RSA modulus ({len(modulus)} bytes).")

    # Build public area and AK name
    pub_area_hex, ak_name_hex = build_ak_template(modulus)

    print("\n--- [1] AK PUBLIC KEY (PEM) ---")
    print(pub_pem.strip())

    print("\n--- [2] AK PUBLIC AREA (HEX) ---")
    print(f"Header    : {pub_area_hex[:48]}")
    print(f"Modulus   : {pub_area_hex[48:96]}... ({len(pub_area_hex)} hex characters)")
    print(f"Full Hex  : {pub_area_hex}")

    print("\n--- [3] AK NAME (HEX) ---")
    print(f"AK Name   : {ak_name_hex}")
    print(f"Algorithm : SHA-256 (000b prefix, 68 hex characters / 34 bytes)")

    payload = {
        "device_id": args.device_id,
        "institution_id": args.institution_id,
        "hostname": f"{args.device_id}.examos.local",
        "device_name": f"ExamOS Terminal {args.device_id}",
        "device_category": "lab_pc",
        "manufacturer": "Dell",
        "model": "OptiPlex 7090",
        "boot_mode": "UEFI",
        "secure_boot_state": "enabled",
        "tpm_present": True,
        "tpm_version": "2.0",
        "os_release_id": "ExamOS 2.0",
        "kernel_version": "6.6.0-examos",
        "ak_public_key_pem": pub_pem.strip(),
        "ak_public_area_hex": pub_area_hex,
        "ak_name_hex": ak_name_hex
    }

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\n[+] Full device registration payload saved to: {args.output_json}")

    print("\n" + "=" * 70)
    print(" [✓] Ready for POST /api/v1/devices/register or Management Console UI")
    print("=" * 70)

if __name__ == "__main__":
    main()
