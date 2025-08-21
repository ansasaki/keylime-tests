#!/bin/bash
# Custom certificate creation script using swtpm_cert to generate malformed EK certificate
# This version uses swtpm_cert which preserves the DN order from the CA certificate

set -e

# Parse command line arguments provided by swtpm_setup
TYPE=""
CERTDIR=""
EKPARAM=""
TPM_SPEC_FAMILY=""
TPM_SPEC_LEVEL=""
TPM_SPEC_REVISION=""
TPM_MANUFACTURER=""
TPM_MODEL=""
TPM_VERSION=""
TPM2=""
CONFIGFILE=""
OPTSFILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            TYPE="$2"
            shift 2
            ;;
        --ek)
            EKPARAM="$2"
            shift 2
            ;;
        --dir)
            CERTDIR="$2"
            shift 2
            ;;
        --tpm-spec-family)
            TPM_SPEC_FAMILY="$2"
            shift 2
            ;;
        --tpm-spec-level)
            TPM_SPEC_LEVEL="$2"
            shift 2
            ;;
        --tpm-spec-revision)
            TPM_SPEC_REVISION="$2"
            shift 2
            ;;
        --tpm-manufacturer)
            TPM_MANUFACTURER="$2"
            shift 2
            ;;
        --tpm-model)
            TPM_MODEL="$2"
            shift 2
            ;;
        --tpm-version)
            TPM_VERSION="$2"
            shift 2
            ;;
        --tpm2)
            TPM2="yes"
            shift
            ;;
        --configfile)
            CONFIGFILE="$2"
            shift 2
            ;;
        --optsfile)
            OPTSFILE="$2"
            shift 2
            ;;
        *)
            # Skip unknown arguments
            shift
            ;;
    esac
done

# Validate required parameters
if [[ -z "$TYPE" || -z "$CERTDIR" ]]; then
    echo "Error: Missing required parameters --type and/or --dir"
    exit 1
fi

# Create certificates directory
mkdir -p "$CERTDIR"

# Generate CA private key
openssl genrsa -out "$CERTDIR/rootca-key.pem" 2048

# Create CA certificate with proper DN ordering (C, O, CN - standard order)
# The CA certificate should be valid for normal parsing and verification
openssl req -new -x509 -key "$CERTDIR/rootca-key.pem" -out "$CERTDIR/rootca-cert.pem" \
    -days 3650 -subj "/C=US/O=Test TPM CA/CN=Test TPM Root CA"

echo "Created CA certificate with proper DN order:"
openssl x509 -in "$CERTDIR/rootca-cert.pem" -subject -noout

# Generate certificates based on the type requested
case "$TYPE" in
    "ek")
        # We need to extract the actual EK public key from the parameter passed by swtpm_setup
        # The EKPARAM contains the EK key information that we need to parse
        
        if [[ -n "$EKPARAM" ]]; then
            # Parse the EK parameter - it might be in different formats
            # For now, let's try to use it as a modulus/exponent or key data
            echo "EK parameter received: $EKPARAM"
            
            # Try to parse as hex modulus (most common for RSA)
            if [[ ${#EKPARAM} -gt 400 ]]; then
                # This looks like a hex-encoded RSA modulus
                # First create a normal certificate, then we'll modify it to be malformed
                SWTPM_CERT_ARGS=(
                    --type ek
                    --modulus "$EKPARAM"
                    --exponent 65537
                    --signkey "$CERTDIR/rootca-key.pem"
                    --issuercert "$CERTDIR/rootca-cert.pem"
                    --out-cert "$CERTDIR/ek.cert"
                    --subject "CN=Malformed EK Certificate,O=Test TPM EK,C=US"
                    --decryption
                )
                
                # Add TPM2 flag if specified
                [[ "$TPM2" == "yes" ]] && SWTPM_CERT_ARGS+=(--tpm2)
                
                # Add TPM parameters if provided
                [[ -n "$TPM_MANUFACTURER" ]] && SWTPM_CERT_ARGS+=(--tpm-manufacturer "$TPM_MANUFACTURER")
                [[ -n "$TPM_MODEL" ]] && SWTPM_CERT_ARGS+=(--tpm-model "$TPM_MODEL")
                [[ -n "$TPM_VERSION" ]] && SWTPM_CERT_ARGS+=(--tpm-version "$TPM_VERSION")
                [[ -n "$TPM_SPEC_FAMILY" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-family "$TPM_SPEC_FAMILY")
                [[ -n "$TPM_SPEC_LEVEL" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-level "$TPM_SPEC_LEVEL")
                [[ -n "$TPM_SPEC_REVISION" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-revision "$TPM_SPEC_REVISION")
                
                swtpm_cert "${SWTPM_CERT_ARGS[@]}"
            else
                # Fallback: generate our own key and fix the validation issue later
                openssl genrsa -out "$CERTDIR/ek-key.pem" 2048
                openssl rsa -in "$CERTDIR/ek-key.pem" -pubout -out "$CERTDIR/ek-pubkey.pem"
                
                SWTPM_CERT_ARGS=(
                    --type ek
                    --pubkey "$CERTDIR/ek-pubkey.pem"
                    --signkey "$CERTDIR/rootca-key.pem"
                    --issuercert "$CERTDIR/rootca-cert.pem"
                    --out-cert "$CERTDIR/ek.cert"
                    --subject "CN=Malformed EK Certificate,O=Test TPM EK,C=US"
                    --decryption
                )
                
                # Add TPM2 flag if specified
                [[ "$TPM2" == "yes" ]] && SWTPM_CERT_ARGS+=(--tpm2)
                
                # Add TPM parameters if provided
                [[ -n "$TPM_MANUFACTURER" ]] && SWTPM_CERT_ARGS+=(--tpm-manufacturer "$TPM_MANUFACTURER")
                [[ -n "$TPM_MODEL" ]] && SWTPM_CERT_ARGS+=(--tpm-model "$TPM_MODEL")
                [[ -n "$TPM_VERSION" ]] && SWTPM_CERT_ARGS+=(--tpm-version "$TPM_VERSION")
                [[ -n "$TPM_SPEC_FAMILY" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-family "$TPM_SPEC_FAMILY")
                [[ -n "$TPM_SPEC_LEVEL" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-level "$TPM_SPEC_LEVEL")
                [[ -n "$TPM_SPEC_REVISION" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-revision "$TPM_SPEC_REVISION")
                
                swtpm_cert "${SWTPM_CERT_ARGS[@]}"
            fi
        else
            echo "No EK parameter provided, generating our own key"
            openssl genrsa -out "$CERTDIR/ek-key.pem" 2048
            openssl rsa -in "$CERTDIR/ek-key.pem" -pubout -out "$CERTDIR/ek-pubkey.pem"
            
            SWTPM_CERT_ARGS=(
                --type ek
                --pubkey "$CERTDIR/ek-pubkey.pem"
                --signkey "$CERTDIR/rootca-key.pem"
                --issuercert "$CERTDIR/rootca-cert.pem"
                --out-cert "$CERTDIR/ek.cert"
                --subject "CN=Malformed EK Certificate,O=Test TPM EK,C=US"
                --decryption
            )
        fi

        echo "Created EK certificate with malformed subject DN using swtpm_cert"
        echo "EK certificate subject DN (malformed order):"
        openssl x509 -in "$CERTDIR/ek.cert" -subject -noout
        echo "EK certificate issuer DN (properly formatted):"
        openssl x509 -in "$CERTDIR/ek.cert" -issuer -noout

        # List all files created for debugging
        echo "Files created in $CERTDIR:"
        ls -la "$CERTDIR/" || true
        
        # Only remove clearly temporary files - keep everything else for swtpm_setup
        rm -f "$CERTDIR/ek-pubkey.pem"
        ;;

    "platform")
        # Generate RSA key for platform certificate
        openssl genrsa -out "$CERTDIR/platform-key.pem" 2048

        # Extract public key for swtpm_cert
        openssl rsa -in "$CERTDIR/platform-key.pem" -pubout -out "$CERTDIR/platform-pubkey.pem"

        # Use swtpm_cert to create platform certificate (with properly sorted DN for comparison)
        # Create a properly sorted CA for platform certificate
        openssl genrsa -out "$CERTDIR/platform-ca-key.pem" 2048
        openssl req -new -x509 -key "$CERTDIR/platform-ca-key.pem" -out "$CERTDIR/platform-ca-cert.pem" \
            -days 3650 -subj "/C=US/O=Test TPM Platform CA/CN=Test TPM Platform Root CA"

        SWTPM_CERT_ARGS=(
            --type platform
            --pubkey "$CERTDIR/platform-pubkey.pem"
            --signkey "$CERTDIR/platform-ca-key.pem"
            --issuercert "$CERTDIR/platform-ca-cert.pem"
            --out-cert "$CERTDIR/platform.cert"
        )
        
        # Add TPM2 flag if specified
        [[ "$TPM2" == "yes" ]] && SWTPM_CERT_ARGS+=(--tpm2)
        
        # Add TPM parameters (platform certificates require tpm-manufacturer, tpm-model, and tmp-version)
        # Use provided values or sensible defaults
        SWTPM_CERT_ARGS+=(--platform-manufacturer "${TPM_MANUFACTURER:-Test Platform Manufacturer}")
        SWTPM_CERT_ARGS+=(--platform-model "${TPM_MODEL:-Test Platform Model}")
        SWTPM_CERT_ARGS+=(--platform-version "${TPM_VERSION:-1.0}")
        
        # Also add the TPM parameters that platform certificates need
        SWTPM_CERT_ARGS+=(--tpm-manufacturer "${TPM_MANUFACTURER:-Test Manufacturer}")
        SWTPM_CERT_ARGS+=(--tpm-model "${TPM_MODEL:-Test Model}")
        SWTPM_CERT_ARGS+=(--tpm-version "${TPM_VERSION:-1.0}")
        
        [[ -n "$TPM_SPEC_FAMILY" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-family "$TPM_SPEC_FAMILY")
        [[ -n "$TPM_SPEC_LEVEL" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-level "$TPM_SPEC_LEVEL")
        [[ -n "$TPM_SPEC_REVISION" ]] && SWTPM_CERT_ARGS+=(--tpm-spec-revision "$TPM_SPEC_REVISION")
        
        swtpm_cert "${SWTPM_CERT_ARGS[@]}"

        echo "Created platform certificate with swtpm_cert"
        echo "Platform certificate issuer DN (properly sorted):"
        openssl x509 -in "$CERTDIR/platform.cert" -issuer -noout

        # List all files created for debugging
        echo "Files created in $CERTDIR:"
        ls -la "$CERTDIR/" || true
        
        # Only remove clearly temporary files - keep everything else for swtpm_setup
        rm -f "$CERTDIR/platform-pubkey.pem"
        ;;

    *)
        echo "Unknown certificate type: $TYPE"
        exit 1
        ;;
esac

# Copy all generated certificates and keys to test directory if requested
if [ -n "$KEYLIME_TEST_CERT_DIR" ] && [ -d "$KEYLIME_TEST_CERT_DIR" ]; then
    echo "Copying all certificates and keys to test directory: $KEYLIME_TEST_CERT_DIR"
    
    # Copy all certificate and key files that were generated
    for file in "$CERTDIR"/*.cert "$CERTDIR"/*.pem "$CERTDIR"/*.key; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            echo "Copying $filename to $KEYLIME_TEST_CERT_DIR"
            cp "$file" "$KEYLIME_TEST_CERT_DIR/" 2>/dev/null || echo "Warning: Failed to copy $filename"
        fi
    done
    
    echo "Certificate copying completed"
else
    echo "KEYLIME_TEST_CERT_DIR not set or directory doesn't exist, skipping certificate copy"
fi

exit 0
