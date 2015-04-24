#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/openssl/Library/certgen
#   Description: Library for creating X.509 certificates for any use
#   Author: Hubert Kario <hkario@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2014 Red Hat, Inc.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="openssl"

rlJournalStart
    rlPhaseStartSetup
        rlRun "rlImport openssl/certgen"
        if rlIsRHEL '<6'; then
            x509FORMAT="+%y%m%d%H%M%SZ"
        fi
        . ./lib.sh
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "Sanity check"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        rlAssertExists "ca"
        rlAssertExists "server"
        rlAssertExists "server/$x509PKEY"
        rlAssertExists "server/$x509CERT"
        rlRun -s "x509DumpCert ca"
        # check default subject name
        rlAssertGrep "Example CA" "$rlRun_LOG"
        # check extensions
        rlAssertGrep "Subject Key Identifier" "$rlRun_LOG"
        rlAssertGrep "Authority Key Identifier" "$rlRun_LOG"
        rlAssertGrep "Key Usage:.*critical" "$rlRun_LOG"
        rlAssertGrep "Basic Constraints:.*critical" "$rlRun_LOG"
        rlAssertGrep "Certificate Sign" "$rlRun_LOG"
        rlAssertGrep "CRL Sign" "$rlRun_LOG"
        rlAssertGrep "CA:TRUE" "$rlRun_LOG"
        rlAssertNotGrep "Subject Alternative Name" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Example CA" "$rlRun_LOG"
        rlAssertGrep "localhost" "$rlRun_LOG"
        rlAssertGrep "Key Usage:.*critical" "$rlRun_LOG"
        rlAssertGrep "Digital Signature" "$rlRun_LOG"
        rlAssertGrep "Key Encipherment" "$rlRun_LOG"
        rlAssertGrep "Key Agreement" "$rlRun_LOG"
        rlAssertGrep "Extended Key Usage" "$rlRun_LOG"
        rlAssertGrep "TLS Web Server Authentication" "$rlRun_LOG"
        rlAssertGrep "Subject Key Identifier" "$rlRun_LOG"
        rlAssertGrep "Authority Key Identifier" "$rlRun_LOG"
        rlAssertNotGrep "Subject Alternative Name" "$rlRun_LOG"
        rlAssertNotGrep "Basic Constraints" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"
        rlAssertExists "$(x509Key server)"
        rlAssertExists "$(x509Cert server)"
        rlAssertExists "$(x509Key --der server)"
        rlAssertExists "$(x509Cert --der server)"
        rlAssertNotEquals "PEM and DER key files should have different names" "$(x509Key server)" "$(x509Key --der server)"
        rlAssertNotEquals "PEM and DER cert files should have different names" "$(x509Cert server)" "$(x509Cert --der server)"
        rlAssertDiffer "$(x509Key server)" "$(x509Key --der server)"
        rlAssertDiffer "$(x509Cert server)" "$(x509Cert --der server)"
        a=$(openssl rsa -modulus -in $(x509Key server) -noout)
        b=$(openssl rsa -modulus -in $(x509Key server --der) -inform DER -noout)
        rlRun "[[ $a == $b ]]" 0 "Check if files have the same private key inside"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    if ! rlIsRHEL '<6' && ! rlIsRHEL '<6.5'; then
        rlPhaseStartTest "ECDSA support"
            rlRun "x509KeyGen -t ecdsa ca"
            rlRun "x509KeyGen -t ecdsa server"
            rlRun "x509SelfSign ca"
            rlRun "x509CertSign --CA ca server"
            rlAssertExists "$(x509Cert server)"
            rlRun -s "x509DumpCert server"
            rlAssertGrep "prime256v1" "$rlRun_LOG"
            rlAssertGrep "ecdsa-with-SHA256" "$rlRun_LOG"
            rlRun "rm '$rlRun_LOG'"
            rlRun "x509RmAlias ca"
            rlRun "x509RmAlias server"
        rlPhaseEnd
    fi

    rlPhaseStartTest "DSA support"
        rlRun "x509KeyGen -t dsa ca"
        rlRun "x509KeyGen -t dsa server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        rlAssertExists "$(x509Cert server)"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "dsaEncryption" "$rlRun_LOG"
        # DSA with SHA256 is unsupported with old OpenSSL (<1.0.0)
        if rlIsRHEL 5; then
            rlAssertGrep "dsaWithSHA1" "$rlRun_LOG"
        else
            rlAssertGrep "dsa_with_SHA256" "$rlRun_LOG"
        fi
        rlRun "rm '$rlRun_LOG'"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Certificate profiles"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen subca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca -t CA subca"
        rlRun "x509CertSign --CA subca server"
        rlAssertExists "$(x509Cert ca)"
        rlAssertExists "$(x509Cert subca)"
        rlAssertExists "$(x509Cert server)"
        rlRun -s "x509DumpCert subca"
        rlAssertGrep "CA:TRUE" "$rlRun_LOG"
        rlAssertGrep "Certificate Sign" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Example intermediate CA" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"
        options=('-CAfile' "$(x509Cert ca)"
            '-untrusted' "$(x509Cert subca)"
            '-x509_strict'
            "$(x509Cert server)")
        rlRun -s "openssl verify ${options[*]}"
        rlAssertGrep "OK" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias subca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Hash for signing"
        rlRun "x509KeyGen ca"
        rlRun "x509SelfSign --md sha512 ca"
        rlRun "x509KeyGen server"
        rlRun "x509CertSign --CA ca --md sha512 server"
        rlRun -s "x509DumpCert ca"
        rlAssertGrep "sha512" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "sha512" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Custom DN"
        rlRun "x509KeyGen ca"
        rlRun "x509SelfSign ca"
        rlRun "x509KeyGen server"
        rlRun "x509CertSign --CA ca --DN 'O=RedHat Test' --DN 'OU=Quality Engineering' server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "RedHat Test" "$rlRun_LOG"
        rlAssertGrep "Quality Engineering" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Extended Key Usage"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca --extendedKeyUsage critical,timeStamping server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Extended Key Usage:.*critical" "$rlRun_LOG"
        rlAssertGrep "Time Stamping" "$rlRun_LOG"
        rlAssertNotGrep "Web Server Authentication" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "OCSP no check"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca --ocspNoCheck server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "OCSP No Check" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "OCSP responder URL"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca --ocspResponderURI http://ocsp.example.com server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Authority Information Access" "$rlRun_LOG"
        rlAssertGrep "ocsp[.]example[.]com" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Subject Alt Name"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        options=(
            '--subjectAltNameCritical'
            '--subjectAltName' 'DNS.1=example.com'
            '--subjectAltName' 'DNS.2=localhost'
            '--subjectAltName' 'IP.1=192.168.0.1'
            '--subjectAltName' 'IP.2=::1'
            )
        rlRun "x509CertSign --CA ca --DN 'O=Test' ${options[*]} server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Subject Alternative Name.*critical" "$rlRun_LOG"
        rlAssertGrep "example[.]com" "$rlRun_LOG"
        rlAssertGrep "localhost" "$rlRun_LOG"
        rlAssertGrep "192[.]168[.]0[.]1" "$rlRun_LOG"
        rlAssertGrep "0:0:0:0:0:0:0:1" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Certificate validity period"
        rlRun "x509KeyGen ca"
        rlRun "x509SelfSign --notBefore '20100101Z' --notAfter '20300101Z' ca"
        rlRun -s "x509DumpCert ca"
        rlAssertGrep "Not Before: Jan  1 00:00:00 2010 GMT" "$rlRun_LOG"
        rlAssertGrep "Not After : Jan  1 00:00:00 2030 GMT" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
