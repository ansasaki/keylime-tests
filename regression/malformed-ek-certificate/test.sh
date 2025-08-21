#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

AGENT_ID="d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

rlJournalStart

    rlPhaseStartSetup "Setup custom swtpm with malformed EK certificate"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import keylime-tests/test-helpers library"
        rlAssertRpm keylime
        rlAssertRpm swtpm
        rlAssertRpm swtpm-tools

        # Ensure swtpm_cert is available for certificate generation
        which swtpm_cert || rlDie "swtpm_cert not found - required for malformed certificate generation"

        # Backup original configuration
        limeBackupConfig

        # Configure keylime for EK certificate verification
        rlRun "limeUpdateConf tenant require_ek_cert true"

        # Setup custom swtpm with malformed certificates
        TESTDIR=$(limeCreateTestDir)
        SWTPM_DIR="${TESTDIR}/swtpm"
        rlRun "mkdir -p $SWTPM_DIR"

        # Update swtpm config to use our test directory path
        sed "s|TESTDIR|$TESTDIR|g" "swtpm_setup.conf" > "${SWTPM_DIR}/swtpm_setup.conf"

        # Copy the custom certificate generation script to the test directory
        rlRun "cp create_malformed_certs.sh $TESTDIR"

        # Set environment variable for our script to know where to copy certificates
        export KEYLIME_TEST_CERT_DIR="$SWTPM_DIR"

        # Create malformed certificates using our custom script
        rlRun "swtpm_setup --tpm-state $SWTPM_DIR --createek --decryption \
            --create-ek-cert --create-platform-cert \
            --config $SWTPM_DIR/swtpm_setup.conf \
            --lock-nvram --overwrite --display --tpm2 \
            --pcr-banks sha256"

        # Verify that certificates were created
        rlAssertExists "$SWTPM_DIR/ek.cert"
        rlAssertExists "$SWTPM_DIR/platform.cert"

        # Debug: Check what the EK certificate actually contains
        rlRun -s "openssl x509 -in $SWTPM_DIR/ek.cert -text -noout"
        rlLogInfo "Complete EK certificate details:"
        cat $rlRun_LOG
        
        # Check the actual subject DN
        rlRun -s "openssl x509 -in $SWTPM_DIR/ek.cert -subject -noout"
        rlLogInfo "EK certificate subject DN:"
        cat $rlRun_LOG
        
        # Check the actual issuer DN
        rlRun -s "openssl x509 -in $SWTPM_DIR/ek.cert -issuer -noout"
        rlLogInfo "EK certificate issuer DN:"
        cat $rlRun_LOG
        # Verify that the EK certificate is valid even though is malformed
        rlRun "openssl verify -CAfile $SWTPM_DIR/rootca-cert.pem $SWTPM_DIR/ek.cert"

        # Debug: Check which CA certificates we have
        rlLogInfo "Available CA certificates in test directory:"
        ls -la $SWTPM_DIR/*.pem || true
        
        # Check the rootca certificate details
        if [ -f "$SWTPM_DIR/rootca-cert.pem" ]; then
            rlRun -s "openssl x509 -in $SWTPM_DIR/rootca-cert.pem -subject -noout"
            rlLogInfo "Root CA certificate subject:"
            cat $rlRun_LOG
        fi

        # Add our CA certificate to keylime's certificate store for EK verification
        rlRun "mkdir -p /var/lib/keylime/tpm_cert_store"
        rlRun "cp $SWTPM_DIR/rootca-cert.pem /var/lib/keylime/tpm_cert_store/test-tpm-rootca.pem"
        rlRun "chown keylime:keylime /var/lib/keylime/tpm_cert_store/test-tpm-rootca.pem"
        rlRun "chmod 644 /var/lib/keylime/tpm_cert_store/test-tpm-rootca.pem"

        # Start swtpm using socket interface (simpler than vtpm-proxy, no tabrmd needed)
        SWTPM_CTRL_PORT=2322
        SWTPM_SERVER_PORT=2321
        
        # Start swtpm with socket interface
        rlRun "swtpm socket --tpmstate dir=$SWTPM_DIR --log level=1 \
            --ctrl type=tcp,port=$SWTPM_CTRL_PORT \
            --server type=tcp,port=$SWTPM_SERVER_PORT \
            --flags startup-clear --tpm2 --daemon \
            --pid file=$SWTPM_DIR/swtpm.pid"

        # Wait a moment for swtpm to start
        sleep 2
        
        # Send TPM2_Startup command manually if needed
        rlRun "tpm2_startup -c 2>/dev/null || echo 'TPM startup command completed or already started'"

        # Set environment variables for TPM tools to use swtpm directly (no tabrmd)
        export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=$SWTPM_SERVER_PORT"
        export TCTI="$TPM2TOOLS_TCTI"

        # Create systemd drop-in to override TCTI for keylime_agent
        rlRun "mkdir -p /etc/systemd/system/keylime_agent.service.d"
        rlRun "cat > /etc/systemd/system/keylime_agent.service.d/90-malformed-cert-test.conf <<_EOF
[Service]
Environment=\"TPM2TOOLS_TCTI=${TPM2TOOLS_TCTI}\"
Environment=\"TCTI=${TPM2TOOLS_TCTI}\"
_EOF"
        rlRun "systemctl daemon-reload"

        # Test that TPM is working
        rlRun -s "tpm2_pcrread"
        rlAssertGrep "0 : 0x0000000000000000000000000000000000000000" $rlRun_LOG

        # Debug: Check what NVRAM areas exist
        rlRun -s "tpm2_getcap handles-nv-index"
        rlLogInfo "Available NVRAM handles:"
        cat $rlRun_LOG

        # Debug: Try to read and decode the expected EK certificate NVRAM areas
        rlLogInfo "Attempting to read EK certificate from NVRAM 0x1c00002..."
        if tpm2_nvread 0x1c00002 -o "$TESTDIR/nvram_ek.cert" 2>/dev/null; then
            rlLogInfo "Successfully read EK certificate from NVRAM, decoding..."
            rlRun -s "openssl x509 -in $TESTDIR/nvram_ek.cert -inform DER -text -noout"
            rlLogInfo "EK certificate details from NVRAM:"
            cat $rlRun_LOG
            
            rlRun -s "openssl x509 -in $TESTDIR/nvram_ek.cert -inform DER -subject -noout"
            rlLogInfo "EK certificate subject DN from NVRAM:"
            cat $rlRun_LOG
        else
            rlLogInfo "Failed to read EK certificate from NVRAM 0x1c00002"
        fi

        rlLogInfo "Attempting to read Platform certificate from NVRAM 0x1c08000..."
        if tpm2_nvread 0x1c08000 -o "$TESTDIR/nvram_platform.cert" 2>/dev/null; then
            rlLogInfo "Successfully read Platform certificate from NVRAM, decoding..."
            rlRun -s "openssl x509 -in $TESTDIR/nvram_platform.cert -inform DER -text -noout"
            rlLogInfo "Platform certificate details from NVRAM:"
            cat $rlRun_LOG
        else
            rlLogInfo "Failed to read Platform certificate from NVRAM 0x1c08000"
        fi

        # Debug: Check if there are any other EK-related NVRAM areas
        rlLogInfo "Checking for other potential EK certificate NVRAM areas..."
        for nvaddr in 0x1c00001 0x1c00016 0x1c0001c 0x1c0001e; do
            if tpm2_nvread "$nvaddr" -o "$TESTDIR/nvram_test_$nvaddr.cert" 2>/dev/null; then
                rlLogInfo "Found certificate in NVRAM $nvaddr, decoding..."
                rlRun -s "openssl x509 -in $TESTDIR/nvram_test_$nvaddr.cert -inform DER -subject -noout 2>/dev/null || echo 'Not a valid certificate'"
                [[ -s $rlRun_LOG ]] && cat $rlRun_LOG
            fi
        done

        # Start keylime services
        rlRun "limeStartVerifier"
        rlRun "limeWaitForVerifier"
        rlRun "limeStartRegistrar"
        rlRun "limeWaitForRegistrar"
        rlRun "limeStartAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"

        # Create test policy
        limeCreateTestPolicy
    rlPhaseEnd

    rlPhaseStartTest "Test that malformed certificate is corrupted before stored in DB"
        # This should fail because the EK certificate is re-encoded by the
        # registrar using pyasn1, which corrupts the certificate
        rlRun -s "keylime_tenant -u $AGENT_ID --runtime-policy policy.json -f /etc/hostname -c add" 1
        rlAssertGrep -E "(Invalid EK certificate|certificate verification failed|EK.*validation.*failed|Failed to verify EK)" $rlRun_LOG
    rlPhaseEnd

    rlPhaseStartTest "Test that custom EK check script allows malformed certificate"
        # Copy custom EK check script to keylime directory
        rlRun "cp custom_ek_check.sh /var/lib/keylime/"
        rlRun "chown keylime:keylime /var/lib/keylime/custom_ek_check.sh"
        rlRun "chmod 500 /var/lib/keylime/custom_ek_check.sh"

        # Configure keylime to use our custom EK check script
        rlRun "limeUpdateConf tenant ek_check_script /var/lib/keylime/custom_ek_check.sh"

        # Restart agent service to re-register
        rlRun "limeStopAgent"
        sleep 1
        rlRun "limeStartAgent"
        rlRun "limeWaitForAgentRegistration ${AGENT_ID}"

        # This should now succeed because our custom script validates the certificate
        rlRun -s "keylime_tenant -u $AGENT_ID --runtime-policy policy.json -f /etc/hostname -c update"
        rlAssertGrep "Custom EK check script called for agent" $rlRun_LOG
        rlAssertGrep "EK certificate validation completed successfully" $rlRun_LOG

        # Verify agent is in the correct state
        rlRun "limeWaitForAgentStatus $AGENT_ID 'Get Quote'"
        rlRun -s "keylime_tenant -c cvlist"
        rlAssertGrep "{'code': 200, 'status': 'Success', 'results': {'uuids':.*'$AGENT_ID'" $rlRun_LOG -E
    rlPhaseEnd

    rlPhaseStartCleanup "Cleanup test environment"
        rlRun "limeStopAgent"
        rlRun "limeStopRegistrar"
        rlRun "limeStopVerifier"

        # Stop swtpm daemon
        if [ -f "$SWTPM_DIR/swtpm.pid" ]; then
            rlRun "kill $(cat $SWTPM_DIR/swtpm.pid)" || true
            sleep 1
        fi

        # Clean up systemd drop-in configuration
        rlRun "rm -f /etc/systemd/system/keylime_agent.service.d/90-malformed-cert-test.conf"
        rlRun "systemctl daemon-reload"

        # Clean up CA certificate from keylime certificate store
        rlRun "rm -f /var/lib/keylime/tpm_cert_store/test-tpm-rootca.pem"

        # Clean up temporary files
        limeSubmitCommonLogs
        limeClearData
        limeRestoreConfig
        rlRun "rm -f /var/lib/keylime/custom_ek_check.sh"
        limeExtendNextExcludelist "$TESTDIR"
        rlRun "rm -rf $TESTDIR"
    rlPhaseEnd

rlJournalEnd
