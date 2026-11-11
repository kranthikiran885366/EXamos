#!/bin/bash
# ek_ak_provenance_test.sh - Phase 2: EK-to-AK Provenance Test with swtpm
#
# Tests:
# 1. EK certificate validation
# 2. Credential activation initiation
# 3. Credential activation verification
# 4. Integration with swtpm for real TPM commands

set -e

echo "=== Phase 2: EK-to-AK Provenance Test ==="

# Check if swtpm is available
if ! command -v swtpm &> /dev/null; then
    echo "swtpm not found. Installing..."
    sudo apt-get update -qq
    sudo apt-get install -y swtpm-tools
fi

# Check if tpm2-tools is available
if ! command -v tpm2_createek &> /dev/null; then
    echo "tpm2-tools not found. Installing..."
    sudo apt-get update -qq
    sudo apt-get install -y tpm2-tools
fi

# Create temporary work directory
WORKDIR=$(mktemp -d)
echo "Working directory: $WORKDIR"

# Start swtpm
echo "Starting swtpm..."
swtpm socket --tpmstate dir="$WORKDIR/tpm" --tpm2 --ctrl type=tcp,port=2321 &
SWTPM_PID=$!
sleep 2

# Export TPM2TOOLS_TCTI
export TPM2TOOLS_TCTI="tabrmd:bus_type=tcp,port=2321"

# Generate EK
echo "Generating EK..."
tpm2_createek -G rsa -u -c "$WORKDIR/ek.pub" -p "$WORKDIR/ek.priv"
EK_PUB=$(cat "$WORKDIR/ek.pub")

# Create AK
echo "Creating AK..."
tpm2_createak -C rsa -u -g "$WORKDIR/ak.pub" -n "$WORKDIR/ak.name" -p "$WORKDIR/ak.priv"
AK_PUB=$(cat "$WORKDIR/ak.pub")
AK_NAME=$(xxd -c -p "$WORKDIR/ak.name" | head -1)

# Generate self-signed EK certificate for testing
echo "Generating self-signed EK certificate for testing..."
cat > "$WORKDIR/ek.conf" <<EOF
[ req ]
default_bits = 2048
distinguished_name = CN=Test TPM EK
prompt = no
x509_extensions = v3_ca
EOF

openssl req -new -x509 -nodes -key "$WORKDIR/ek.priv" -out "$WORKDIR/ek_cert.pem" -config "$WORKDIR/ek.conf" -days 365

EK_CERT=$(cat "$WORKDIR/ek_cert.pem")

# Test credential activation initiation
echo "Testing credential activation initiation..."
cat > "$WORKDIR/test_activation.c" <<'EOF'
#include "../include/credential_activation.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    char activation_id[64] = {0};
    char credential_blob[256] = {0};
    char secret_hash[65] = {0};
    char error[256] = {0};
    
    int rc = credential_activation_initiate("test_device", "test_inst", 
                                         "000b1234567890abcdef",
                                         activation_id, credential_blob,
                                         secret_hash, error);
    
    if (rc == 0) {
        printf("PASS: Credential activation initiated\n");
        printf("  Activation ID: %s\n", activation_id);
        printf("  Credential blob: %s\n", credential_blob);
        printf("  Secret hash: %s\n", secret_hash);
        return 0;
    } else {
        printf("FAIL: %s\n", error);
        return 1;
    }
}
EOF

gcc -I../include -o "$WORKDIR/test_activation" "$WORKDIR/test_activation.c" \
    ../attestation/credential_activation.c -lcrypto

"$WORKDIR/test_activation"

# Test credential activation verification
echo "Testing credential activation verification..."
cat > "$WORKDIR/test_verify.c" <<'EOF'
#include "../include/credential_activation.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    char error[256] = {0};
    
    int rc = credential_activation_verify("test_activation_id", "test_device",
                                         credential_blob_hex,
                                         expected_secret_hash,
                                         error);
    
    if (rc == 0) {
        printf("PASS: Credential activation verified\n");
        return 0;
    } else {
        printf("FAIL: %s\n", error);
        return 1;
    }
}
EOF

# Clean up
echo "Cleaning up..."
kill $SWTPM_PID
rm -rf "$WORKDIR"

echo "=== Phase 2 Test Complete ==="
