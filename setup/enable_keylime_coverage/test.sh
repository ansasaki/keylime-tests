#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
. /usr/share/beakerlib/beakerlib.sh || exit 1

rlJournalStart

    rlPhaseStartSetup "Install coverage script its dependencies"
        rlRun 'rlImport "./test-helpers"' || rlDie "cannot import keylime-tests/test-helpers library"
        rpm -q python3-coverage && rlRun "rpm -e python3-coverage"
        rlRun "pip3 install coverage"
        INSTALL_DIR=$( dirname $(find /usr/local/lib*/python*/site-packages -name coverage ) )
        rlRun "touch $__INTERNAL_limeCoverageDir/enabled"
    rlPhaseEnd

    rlPhaseStartTest "Check if the coverage script is installed"
        rlRun "coverage --version"
    rlPhaseEnd

    rlPhaseStartSetup "Modify keylime systemd unit files"
        id keylime && rlRun "chown -R keylime /var/tmp/limeLib && chmod -R g+w /var/tmp/limeLib"
        LOCAL_LIBDIR=$( ls -d /usr/local/lib/python*/site-packages )
        SYSTEM_LIBDIR=$( ls -d /usr/lib/python*/site-packages )
        if rpm -q keylime-99 &> /dev/null; then
            LIBDIR=${LOCAL_LIBDIR}
        else
            LIBDIR=${SYSTEM_LIBDIR}
        fi
	rlRun "cat > ${LIBDIR}/sitecustomize.py <<_EOF
import sys
if 'coverage' not in sys.modules:
    sys.path.append(\"${INSTALL_DIR}\")
    import coverage
    coverage.process_startup()
_EOF"
        grep -q COVERAGE_PROCESS_START /etc/bashrc || rlRun "echo 'export COVERAGE_PROCESS_START=/var/tmp/limeLib/coverage/coveragerc' >> /etc/bashrc"
        SERVICES="verifier registrar"
        limeIsPythonAgent && SERVICES="${SERVICES} agent"
        for F in ${SERVICES}; do
            rlRun "mkdir -p /etc/systemd/system/keylime_${F}.service.d"
            rlRun "cat > /etc/systemd/system/keylime_${F}.service.d/10-coverage.conf <<_EOF
[Service]
# set variable containing name of the currently running test
Environment=\"COVERAGE_PROCESS_START=/var/tmp/limeLib/coverage/coveragerc\"
# we need to change WorkingDirectory since .coverage* files will be stored there
WorkingDirectory=/var/tmp/limeLib/coverage
_EOF"
        done
	rlRun "systemctl daemon-reload"
    rlPhaseEnd

    rlPhaseStartTest "Injecting .coverage archiving code into rlRun"

        BEAKERLIB_SCRIPT=/usr/share/beakerlib/testing.sh

        if grep -q "__INTERNAL_limeCoverageDir" $BEAKERLIB_SCRIPT; then
            rlLogInfo "Archiving code has been already injected into $BEAKERLIB_SCRIPT"
        else
            rlRun "cp $BEAKERLIB_SCRIPT $BEAKERLIB_SCRIPT.pre_injection_backup.$$" 0 "Making backup of $BEAKERLIB_SCRIPT"
            # modify rlRun()
            CODE=$(cat <<_EOF
\[ -n "\$__INTERNAL_limeCoverageDir" \] && \[ "\$PWD" != "\$__INTERNAL_limeCoverageDir" \] && ls .coverage.* &>/dev/null &&  cp -u .coverage.* "\${__INTERNAL_limeCoverageDir}/" &>/dev/null || :
_EOF
)
            rlRun "sed -i '/return \$__INTERNAL_rlRun_exitcode/ i\ ${CODE}\ ' $BEAKERLIB_SCRIPT"
            grep -B 3 'return $__INTERNAL_rlRun_exitcode' $BEAKERLIB_SCRIPT
        fi
    rlPhaseEnd

rlJournalEnd
