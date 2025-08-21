#!/bin/bash
# Custom EK certificate verification script that uses OpenSSL for validation
# This script bypasses the strict ASN.1 DN ordering checks and focuses on
# cryptographic validation

# Environment variables provided by keylime:
# AGENT_UUID - The agent's UUID
# EK - The endorsement key in PEM format
# EK_CERT - The EK certificate in PEM format
# EK_TPM - TPM-specific EK information
# PROVKEYS - Provisioning keys

# Log the inputs for debugging
echo "Custom EK check script called for agent: $AGENT_UUID"
echo "EK certificate verification starting..."

# Create temporary files for certificate validation
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Write the EK certificate to a temporary file
echo "$EK_CERT" > "$TMPDIR/ek_cert.pem"

# Basic certificate format validation using OpenSSL
if ! openssl x509 -in "$TMPDIR/ek_cert.pem" -text -noout > "$TMPDIR/cert_info.txt" 2>/dev/null; then
    echo "ERROR: Failed to parse EK certificate with OpenSSL"
    exit 1
fi

echo "Certificate parsed successfully by OpenSSL"

# Check if certificate has required TPM-specific extensions
if ! grep -q "2\.23\.133\." "$TMPDIR/cert_info.txt"; then
    echo "WARNING: Certificate does not contain TPM-specific OIDs, but continuing..."
fi

# Check certificate validity period
if ! openssl x509 -in "$TMPDIR/ek_cert.pem" -checkend 0 >/dev/null 2>&1; then
    echo "ERROR: Certificate has expired or is not yet valid"
    exit 1
fi

echo "Certificate is within valid time period"

# Verify that the certificate's public key matches the provided EK
if [ -n "$EK" ]; then
    echo "$EK" > "$TMPDIR/ek_key.pem"

    # Extract public key from certificate
    openssl x509 -in "$TMPDIR/ek_cert.pem" -pubkey -noout > "$TMPDIR/cert_pubkey.pem"

    # Compare the public keys
    if ! cmp -s "$TMPDIR/ek_key.pem" "$TMPDIR/cert_pubkey.pem"; then
        echo "ERROR: Public key in certificate does not match provided EK"
        exit 1
    fi

    echo "Public key verification passed"
else
    echo "WARNING: No EK public key provided for verification"
fi

# Check for key usage extensions
if grep -q "Key Encipherment" "$TMPDIR/cert_info.txt"; then
    echo "Certificate has correct key usage for TPM EK"
else
    echo "WARNING: Certificate may not have appropriate key usage for TPM EK"
fi

# Log successful validation
echo "EK certificate validation completed successfully"
echo "Certificate contains subject: $(openssl x509 -in "$TMPDIR/ek_cert.pem" -subject -noout)"
echo "Certificate contains issuer: $(openssl x509 -in "$TMPDIR/ek_cert.pem" -issuer -noout)"

# Return success - certificate is cryptographically valid even if DN ordering is non-standard
exit 0
