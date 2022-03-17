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
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="openssl"

fips=$(cat /proc/sys/crypto/fips_enabled)

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlRun "rlImport ./certgen"
        . ./lib.sh
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlLogInfo "fips=$fips"
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

        rlLogInfo "Checking default settings for CA"
        rlRun -s "x509DumpCert ca"
        rlAssertGrep "Example CA" "$rlRun_LOG"
        rlAssertGrep "Subject Key Identifier" "$rlRun_LOG"
        rlAssertGrep "Authority Key Identifier" "$rlRun_LOG"
        rlAssertGrep "Key Usage:.*critical" "$rlRun_LOG"
        rlAssertGrep "Basic Constraints:.*critical" "$rlRun_LOG"
        rlAssertGrep "Certificate Sign" "$rlRun_LOG"
        rlAssertGrep "CRL Sign" "$rlRun_LOG"
        rlAssertGrep "CA:TRUE" "$rlRun_LOG"
        rlAssertNotGrep "Subject Alternative Name" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"

        rlLogInfo "Checking default settings for server certificates"
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

        rlLogInfo "Checking key and certificate export"
        rlAssertExists "$(x509Key server)"
        rlAssertExists "$(x509Cert server)"
        rlAssertExists "$(x509Key --der server)"
        rlAssertExists "$(x509Cert --der server)"
        rlRun "x509Cert --pkcs12 server" 0 "export to PKCS#12 format"
        rlAssertExists "$(x509Cert --pkcs12 server)"
        if ! rlIsRHEL 4; then
            rlRun "grep localhost $(x509Cert --pkcs12 server)" 0 "Check if file is unencrypted"
        fi
        rlRun "rm $(x509Cert --pkcs12 server)"
        rlRun "x509Cert --pkcs12 --password RedHatEnterpriseLinux7.1 server"\
            0 "Test export with encryption"

        rlLogInfo "Checking if exported keys and certs match independent of format"
        rlAssertNotEquals "PEM and DER key files should have different names" \
            "$(x509Key server)" "$(x509Key --der server)"
        rlAssertNotEquals "PEM and DER cert files should have different names" \
            "$(x509Cert server)" "$(x509Cert --der server)"
        rlAssertDiffer "$(x509Key server)" "$(x509Key --der server)"
        rlAssertDiffer "$(x509Cert server)" "$(x509Cert --der server)"
        a=$(openssl rsa -modulus -in $(x509Key server) -noout)
        b=$(openssl rsa -modulus -in $(x509Key server --der) -inform DER -noout)
        rlRun "[[ '$a' == '$b' ]]" 0 "Check if files have the same private key inside"

        rlLogInfo "Clean up for phase"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "PKCS12 handling"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"

        rlLogInfo "Test export of just the key"
        if rlIsRHEL 4; then
            rlRun "x509Key --pkcs12 server" 1
        else
            rlRun "x509Key --pkcs12 server"
            rlAssertExists "$(x509Key --pkcs12 server)"
            rlRun -s "openssl pkcs12 -in $(x509Key --pkcs12 server) -info -passin pass: -nodes"
            rlAssertGrep "server" "$rlRun_LOG"
            rlAssertGrep "BEGIN.*KEY" "$rlRun_LOG" -E
            rlAssertNotGrep "BEGIN CERTIFICATE" "$rlRun_LOG"
            rlRun "rm $rlRun_LOG"
            rlRun "rm $(x509Key --pkcs12 server)"
            rlLogInfo "Test export with password"
            rlRun "x509Key --pkcs12 --password RedHatEnterpriseLinux7.1 server"
            rlRun -s "openssl pkcs12 -in $(x509Key --pkcs12 server) -info -passin pass:RedHatEnterpriseLinux7.1 -nodes"
            rlAssertGrep "server" "$rlRun_LOG"
            rlAssertGrep "BEGIN.*KEY" "$rlRun_LOG" -E
            rlAssertNotGrep "BEGIN CERTIFICATE" "$rlRun_LOG"
            rlRun "rm $rlRun_LOG"
            rlRun "rm $(x509Key --pkcs12 server)"
        fi

        rlLogInfo "Test export of key with certificate"
        rlRun "x509Key --pkcs12 --with-cert server"
        rlAssertExists "$(x509Key --pkcs12 --with-cert server)"
        rlRun -s "openssl pkcs12 -in $(x509Key --pkcs12 server) -info -passin pass: -nodes"
        rlAssertGrep "server" "$rlRun_LOG"
        rlAssertGrep "BEGIN.*KEY" "$rlRun_LOG" -E
        rlAssertGrep "BEGIN CERTIFICATE" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"

        rlLogInfo "Check invalid option handling"
        rlRun "x509Key --der --pkcs12 server" 1

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

    # run only on RHEL-8 in normal mode
    if ! rlIsRHEL '<8' && [[ $fips -eq 0 ]]; then
        rlPhaseStartTest "EdDSA ed25519 support"
            rlRun "x509KeyGen -t ed25519 ca"
            rlRun "x509KeyGen -t ed25519 server"
            rlRun "x509SelfSign ca"
            rlRun "x509CertSign --CA ca server"
            rlAssertExists "$(x509Cert server)"
            rlRun -s "x509DumpCert server"
            rlAssertGrep "Signature Algorithm: ED25519" "$rlRun_LOG"
            rlRun "rm '$rlRun_LOG'"
            rlRun "x509RmAlias ca"
            rlRun "x509RmAlias server"
        rlPhaseEnd

        rlPhaseStartTest "EdDSA ed448 support"
            rlRun "x509KeyGen -t ed448 ca"
            rlRun "x509KeyGen -t ed448 server"
            rlRun "x509SelfSign ca"
            rlRun "x509CertSign --CA ca server"
            rlAssertExists "$(x509Cert server)"
            rlRun -s "x509DumpCert server"
            rlAssertGrep "Signature Algorithm: ED448" "$rlRun_LOG"
            rlRun "rm '$rlRun_LOG'"
            rlRun "x509RmAlias ca"
            rlRun "x509RmAlias server"
        rlPhaseEnd
    fi

    # DSA is not supported on RHEL-9 in FIPS mode
    if rlIsRHEL '<9' || [[ $fips -eq 0 ]]; then
        rlPhaseStartTest "DSA support"
            rlRun "x509KeyGen -t dsa ca"
            rlRun "x509KeyGen -t dsa server"
            rlRun "x509SelfSign ca"
            rlRun "x509CertSign --CA ca server"
            rlAssertExists "$(x509Cert server)"
            rlAssertDiffer "$(x509Key server)" "$(x509Key server --der)"
            rlAssertExists "$(x509Key server --der)"
            a=$(openssl dsa -modulus -in $(x509Key server --der) -inform DER -noout)
            b=$(openssl dsa -modulus -in $(x509Key server) -noout)
            rlRun "[[ '$a' == '$b' ]]" 0 "Check if files have the same private key inside"
            rlRun -s "x509DumpCert server"
            rlAssertGrep "dsaEncryption" "$rlRun_LOG"
            # DSA with SHA256 is unsupported with old OpenSSL (<1.0.0)
            if rlIsRHEL 4 5; then
                rlAssertGrep "dsaWithSHA1" "$rlRun_LOG"
            else
                rlAssertGrep "dsa_with_SHA256" "$rlRun_LOG"
            fi
            rlRun "rm '$rlRun_LOG'"
            rlRun "x509RmAlias ca"
            rlRun "x509RmAlias server"
        rlPhaseEnd

        rlPhaseStartTest "DSA param reuse"
            rlRun "x509KeyGen -t dsa ca"
            rlRun "x509KeyGen -t dsa --params ca server"
            a=$(openssl dsa -in $(x509Key ca) -noout -text | grep -A 100 '^P:')
            b=$(openssl dsa -in $(x509Key server) -noout -text | grep -A 100 '^P:')
            rlRun "[[ '$a' == '$b' ]]" 0 "Check if parameters are the same"
            rlRun "x509RmAlias ca"
            rlRun "x509RmAlias server"
        rlPhaseEnd
    fi

    # don't run in strict FIPS mode
    if [[ $fips -eq 0 ]]; then
    rlPhaseStartTest "DSA conservative values"
        rlRun "x509KeyGen -t dsa --conservative -s 1024 ca"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text" 0,1 "Dump the key"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'P:' | \
               tail -n 1 | grep ' 00:'"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'G:' | \
               tail -n 1 | grep ' 00:'"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'Q:' | \
               tail -n 1 | grep ' 00:'"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'pub:' | \
               tail -n 1 | grep ' 00:'"
        rlRun "x509RmAlias ca"
    rlPhaseEnd

    rlPhaseStartTest "DSA anti-conservative values"
        rlRun "x509KeyGen -t dsa --anti-conservative -s 1024 ca"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text" 0,1 "Dump the key"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'P:' | \
               tail -n 1 | grep ' 00:'"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'G:' | \
               tail -n 1 | grep -v ' 00:'"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'Q:' | \
               tail -n 1 | grep ' 00:'"
        rlRun "openssl dsa -in $(x509Key ca) -noout -text | grep -A1 'pub:' | \
               tail -n 1 | grep -v ' 00:'"
        rlRun "x509RmAlias ca"
    rlPhaseEnd
    fi

    rlPhaseStartTest "PKCS8 key format"
        algos="rsa dsa ecdsa"
        if rlIsRHEL '<6.5'; then
            algos="rsa dsa";
        fi
        if ( ! rlIsRHEL '<9' ) && [[ $fips -eq 1 ]]; then
            # no DSA support on RHEL-9 in FIPS mode
            algos="rsa ecdsa"
        fi
        for algo in $algos; do
            bits_or_curves="2048 3072"
            if [[ $algo = "ecdsa" ]]; then
                # support for P-521 was added in RHEL-6.6.0
                if rlIsRHEL '<6.6'; then
                    bits_or_curves="secp384r1 prime256v1"
                else
                    bits_or_curves="secp384r1 secp521r1 prime256v1"
                fi
            fi
            for bc in $bits_or_curves; do
                rlRun "x509KeyGen -t $algo -s $bc key"
                rlAssertGrep "-----BEGIN PRIVATE KEY-----" $(x509Key --pkcs8 key)
                rlAssertGrep "-----END PRIVATE KEY-----" $(x509Key --pkcs8 key)
                rlRun "openssl pkcs8 -topk8 -in $(x509Key key) -out pkcs8.key -nocrypt"
                rlRun "diff -u $(x509Key --pkcs8 key) pkcs8.key"
                rlRun "rm -rf pkcs8.key key/"
            done
        done
    rlPhaseEnd

    # RSA-PSS (and alternative padding modes in general) are not supported
    # on OpenSSL 0.9.8
    if ! rlIsRHEL '<6'; then
        rlPhaseStartTest "Signature padding modes"
            rlLogInfo "Default message digest, RSASSA-PSS padding"
            rlRun "x509KeyGen -t rsa ca"
            rlRun "x509SelfSign --padding pss ca"
            rlRun -s "x509DumpCert ca"
            rlAssertGrep "Signature Algorithm: rsassaPss" $rlRun_LOG
            rlAssertGrep "Mask Algorithm: mgf1 with sha256" $rlRun_LOG
            # maximum salt length in bytes for 2048 bit modulus and sha256 hash
            # encoded as hex
            rlAssertGrep "Salt Length: (0x|)DE" $rlRun_LOG -E
            rlRun "x509RmAlias ca"

            rlLogInfo "Default message digest with RSA-PSS and salt len equal to hash size"
            rlRun "x509KeyGen -t rsa ca"
            rlRun "x509KeyGen -t rsa server"
            rlRun "x509KeyGen -t rsa server-salt"
            rlRun "x509SelfSign --padding pss --pssSaltLen -1 ca"
            rlRun -s "x509DumpCert ca"
            rlAssertGrep "Signature Algorithm: rsassaPss" $rlRun_LOG
            rlAssertGrep "Mask Algorithm: mgf1 with sha256" $rlRun_LOG
            # sha256 output length in bytes, encoded as hex
            rlAssertGrep "Salt Length: (0x|)20" $rlRun_LOG -E
            rlRun "x509CertSign --CA ca --padding pss server"
            rlRun -s "x509DumpCert server"
            rlAssertGrep "Signature Algorithm: rsassaPss" $rlRun_LOG
            rlAssertGrep "Mask Algorithm: mgf1 with sha256" $rlRun_LOG
            # maximum salt length in bytes for 2048 bit modulus and sha256 hash
            # encoded as hex
            rlAssertGrep "Salt Length: (0x|)DE" $rlRun_LOG -E
            rlRun "x509CertSign --CA ca --padding pss --pssSaltLen -1 server-salt"
            rlRun -s "x509DumpCert server-salt"
            rlAssertGrep "Signature Algorithm: rsassaPss" $rlRun_LOG
            rlAssertGrep "Mask Algorithm: mgf1 with sha256" $rlRun_LOG
            # sha256 output length in bytes, encoded as hex
            rlAssertGrep "Salt Length: (0x|)20" $rlRun_LOG -E
            rlRun -s "openssl verify -CAfile $(x509Cert ca) $(x509Cert server)"
            rlAssertGrep "OK" "$rlRun_LOG"
            rlRun -s "openssl verify -CAfile $(x509Cert ca) $(x509Cert server-salt)"
            rlAssertGrep "OK" "$rlRun_LOG"
            rlRun "rm $rlRun_LOG"
            rlRun "x509RmAlias ca"
            rlRun "x509RmAlias server"
            rlRun "x509RmAlias server-salt"

            # OpenSSL 1.0.1 and earlier doesn't have full support for RSA-PSS
            if ! rlIsRHEL '<8' || (rlIsRHEL 7 && rlIsRHEL '>=7.4'); then
                rlLogInfo "Mismatched signature hash and MGF1 hash"
                rlRun "x509KeyGen -t rsa ca"
                rlRun "x509KeyGen -t rsa server"
                rlRun "x509SelfSign --padding pss ca"
                rlRun "x509CertSign --CA ca --padding pss --md sha256 --pssMgf1Md sha384 server"
                rlRun -s "x509DumpCert server"
                rlAssertGrep "Signature Algorithm: rsassaPss" $rlRun_LOG
                rlAssertGrep "Mask Algorithm: mgf1 with sha384" $rlRun_LOG
                rlAssertGrep "Hash Algorithm: sha256" $rlRun_LOG
                rlRun "x509RmAlias ca"
                rlRun "x509RmAlias server"
            fi
        rlPhaseEnd
    fi

    # RSA-PSS certificates are only supported with OpenSSL 1.1.1 and later
    if ! ${x509OPENSSL} version | grep -Eq '0[.]9[.]|1[.]0[.]|1[.]1[.]0'; then
        rlPhaseStartTest "RSA-PSS certificates"
            rlRun "x509KeyGen -t rsa-pss ca"
            rlRun -s "${x509OPENSSL} pkey -noout -text -in $(x509Key ca)"
            # check if private key has the RSA-PSS identifier
            if ${x509OPENSSL} version | grep -Eq '1[.]1[.]1'; then
                # OpenSSL 3.0.0 doesn't print the name
                # but does print that there are no PSS restrictions, so we
                # know that the key is RSA-PSS still
                rlAssertGrep "RSA-PSS Private-Key" $rlRun_LOG
            fi
            rlAssertGrep "No PSS parameter restrictions" $rlRun_LOG
            rlAssertGrep "2048 bit" $rlRun_LOG
            rlRun "x509RmAlias ca"
            # check if the command line options work
            rlRun "x509KeyGen -t rsa-pss -s 3072 --gen-opts rsa_pss_keygen_md:sha256 --gen-opts rsa_pss_keygen_saltlen:20 ca"
            rlRun -s "${x509OPENSSL} pkey -noout -text -in $(x509Key ca)"
            if ${x509OPENSSL} version | grep -Eq '1[.]1[.]1'; then
                # OpenSSL 3.0.0 doesn't print the type any more
                rlAssertGrep "RSA-PSS Private-Key" $rlRun_LOG
            fi
            rlAssertGrep "3072 bit" $rlRun_LOG
            rlAssertNotGrep "No PSS parameter restrictions" $rlRun_LOG
            rlAssertGrep "PSS parameter restrictions" $rlRun_LOG
            if ${x509OPENSSL} version | grep -Eq '1[.]1[.]1'; then
                rlAssertGrep "Hash Algorithm: sha256" $rlRun_LOG
                rlAssertGrep "Minimum Salt Length: 0x14" $rlRun_LOG
            else
                # new OpenSSL calls the algorithm differently
                rlAssertGrep "Hash Algorithm: SHA2-256" $rlRun_LOG
                # and doesn't use hex encoding for the length
                rlAssertGrep "Minimum Salt Length: 20" $rlRun_LOG
            fi
            rlRun "x509SelfSign ca"
            rlRun -s "x509DumpCert ca"
            # verify the restrictions are transferred to certificate
            rlRun "grep -A3 'PSS parameter restrictions' $rlRun_LOG > restrictions.txt"
            if ${x509OPENSSL} version | grep -Eq '1[.]1[.]1'; then
                rlAssertGrep "Hash Algorithm: sha256" restrictions.txt
                rlAssertGrep "Minimum Salt Length: 0x14" restrictions.txt
            else
                # new OpenSSL calls the algorithm differently
                rlAssertGrep "Hash Algorithm: SHA2-256" restrictions.txt
                # and doesn't use hex encoding for the length
                rlAssertGrep "Minimum Salt Length: 20" restrictions.txt
            fi
            rlRun "rm $rlRun_LOG restrictions.txt"
            # check if rsa-pss certificate automatically creates rsa-pss
            # signatures
            rlRun "x509RmAlias ca"
            rlRun "x509KeyGen -t rsa-pss ca"
            rlRun "x509SelfSign ca"
            rlRun "x509KeyGen -t rsa-pss server"
            rlRun "x509CertSign --CA ca server"
            rlRun -s "x509DumpCert server"
            if ${x509OPENSSL} version | grep -Eq '1[.]1[.]1'; then
                rlAssertGrep "RSA-PSS Public-Key" $rlRun_LOG
            else
                rlAssertGrep "Public Key Algorithm: rsassaPss" $rlRun_LOG
            fi
            rlAssertGrep "Hash Algorithm: sha256" $rlRun_LOG
            rlAssertGrep "Signature Algorithm: rsassaPss" $rlRun_LOG
            rlRun "rm $rlRun_LOG"
            # check if they can be verified
            rlRun "${x509OPENSSL} verify -CAfile $(x509Cert ca) -purpose sslserver $(x509Cert server)"
            rlRun "x509RmAlias ca"
            rlRun "x509RmAlias server"
        rlPhaseEnd
    fi

    rlPhaseStartTest "Key Identifiers"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign --noSubjKeyId ca"
        rlRun -s "x509DumpCert ca"
        rlAssertNotGrep "Subject Key Identifier" $rlRun_LOG
        # for self-sign --noSubjKeyId implies --noAuthKeyId
        rlAssertNotGrep "Authority Key Identifier" $rlRun_LOG
        rlRun "x509CertSign --CA ca server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Subject Key Identifier" $rlRun_LOG
        rlAssertGrep "Authority Key Identifier" $rlRun_LOG
        # When the CA doesn't have a SPKI, the AKI can be specified as
        # a combination of directory name and serial number
        rlRun "grep -A3 'Authority Key Identifier' > selection.txt $rlRun_LOG"
        rlAssertGrep "DirName" selection.txt -i
        rlAssertGrep "serial" selection.txt -i
        rlRun "rm selection.txt"

        # see if we can control the SKI and AKI individually
        rlRun "x509KeyGen server-two"
        rlRun "x509CertSign --CA ca --noAuthKeyId server-two"
        rlRun -s "x509DumpCert server-two"
        rlAssertGrep "Subject Key Identifier" $rlRun_LOG
        rlAssertNotGrep "Authority Key Identifier" $rlRun_LOG
        rlRun "x509KeyGen server-three"
        rlRun "x509CertSign --CA ca --noAuthKeyId --noSubjKeyId server-three"
        rlRun -s "x509DumpCert server-three"
        rlAssertNotGrep "Subject Key Identifier" $rlRun_LOG
        rlAssertNotGrep "Authority Key Identifier" $rlRun_LOG
        rlRun "x509KeyGen server-four"
        rlRun "x509CertSign --CA ca --noSubjKeyId server-four"
        rlRun -s "x509DumpCert server-four"
        rlAssertNotGrep "Subject Key Identifier" $rlRun_LOG
        rlAssertGrep "Authority Key Identifier" $rlRun_LOG
        rlRun "x509RmAlias server-three"
        rlRun "x509RmAlias server-two"
        rlRun "x509RmAlias server"
        rlRun "x509RmAlias ca"

        # Test also with a CA that has the SPKI
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun -s "x509DumpCert ca"
        rlAssertGrep "Subject Key Identifier" $rlRun_LOG
        rlAssertGrep "Authority Key Identifier" $rlRun_LOG
        rlRun "x509CertSign --CA ca server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Subject Key Identifier" $rlRun_LOG
        rlAssertGrep "Authority Key Identifier" $rlRun_LOG
        rlRun "x509KeyGen server-two"
        rlRun "x509CertSign --CA ca --noAuthKeyId server-two"
        rlRun -s "x509DumpCert server-two"
        rlAssertGrep "Subject Key Identifier" $rlRun_LOG
        rlAssertNotGrep "Authority Key Identifier" $rlRun_LOG
        rlRun "x509RmAlias server-two"
        rlRun "x509RmAlias server"
        rlRun "x509RmAlias ca"
    rlPhaseEnd

    rlPhaseStartTest "Certificate profiles"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen subca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        # type CA
        rlRun "x509CertSign --CA ca -t CA subca"
        # default type - webserver
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
        rlAssertNotGrep "TLS Web Client Authentication" "$rlRun_LOG"
        rlAssertGrep "TLS Web Server Authentication" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"
        options=('-CAfile' "$(x509Cert ca)"
            '-untrusted' "$(x509Cert subca)")
        if ! rlIsRHEL 4; then
            options=(${options[@]} '-x509_strict')
        fi
        options=(${options[@]} "$(x509Cert server)")
        rlRun -s "openssl verify ${options[*]}"
        rlAssertGrep "OK" "$rlRun_LOG"
        rlRun "rm '$rlRun_LOG'"
        rlRun "x509KeyGen client"
        # type webclient
        rlRun "x509CertSign --CA subca -t webclient client"
        rlAssertExists "$(x509Cert client)"
        rlRun -s "x509DumpCert client"
        rlAssertNotGrep "CA:TRUE" "$rlRun_LOG"
        rlAssertNotGrep "Certifcate Sign" "$rlRun_LOG"
        rlAssertGrep "John Smith" "$rlRun_LOG"
        rlAssertGrep "TLS Web Client Authentication" "$rlRun_LOG"
        rlAssertNotGrep "TLS Web Server Authentication" "$rlRun_LOG"
        rlRun "x509KeyGen none"
        # type none - no extensions
        rlRun "x509CertSign --CA subca -t none none"
        rlAssertExists "$(x509Cert none)"
        rlRun -s "x509DumpCert none"
        rlAssertNotGrep "CA:TRUE" "$rlRun_LOG"
        rlAssertNotGrep "Certificate Sign" "$rlRun_LOG"
        rlAssertNotGrep "TLS Web Server Authentication" "$rlRun_LOG"
        rlAssertNotGrep "TLS Web Client Authentication" "$rlRun_LOG"
        rlAssertNotGrep "X509v3 Key Usage" "$rlRun_LOG"
        rlAssertNotGrep "X509v3 Extended Key Usage" "$rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias subca"
        rlRun "x509RmAlias server"
        rlRun "x509RmAlias client"
        rlRun "x509RmAlias none"
    rlPhaseEnd

    rlPhaseStartTest "Self-signed certificate profile"
        rlRun "x509KeyGen ca"
        rlRun "x509SelfSign -t none ca"
        rlRun -s "x509DumpCert ca"
        rlAssertNotGrep "X509v3 Key Usage" "$rlRun_LOG"
        rlAssertNotGrep "X509v3 Extended Key Usage" "$rlRun_LOG"
        rlRun "x509RmAlias ca"
    rlPhaseEnd

    rlPhaseStartTest "Hash for signing"
        hash="sha512"
        if rlIsRHEL 4; then
            hash="md5"
        fi
        rlRun "x509KeyGen ca"
        rlRun "x509SelfSign --md $hash ca"
        rlRun "x509KeyGen server"
        rlRun "x509CertSign --CA ca --md $hash server"
        rlRun -s "x509DumpCert ca"
        rlAssertGrep "$hash" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "$hash" "$rlRun_LOG"
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

    rlPhaseStartTest "Extended Key Usage - timeStamping"
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

    rlPhaseStartTest "Extended Key Usage - ocspSigning"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca --basicKeyUsage critical,digitalSignature,nonRepudiation --extendedKeyUsage critical,ocspSigning server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Extended Key Usage:.*critical" "$rlRun_LOG"
        rlAssertGrep "OCSP Signing" "$rlRun_LOG"
        rlAssertNotGrep "Web Server Authentication" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Extended Key Usage - OCSPSigning - upper case"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca --basicKeyUsage critical,digitalSignature,nonRepudiation --extendedKeyUsage critical,OCSPSigning server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Extended Key Usage:.*critical" "$rlRun_LOG"
        rlAssertGrep "OCSP Signing" "$rlRun_LOG"
        rlAssertNotGrep "Web Server Authentication" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "OCSP no check"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509KeyGen server2"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca --ocspNoCheck server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "OCSP No Check" "$rlRun_LOG"
        rlAssertNotGrep "OCSP No Check: critical" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        # "critical" flag doesn't work on RHEL-4
        if ! rlIsRHEL '<5'; then
            rlRun "x509CertSign --CA ca --ocspNoCheck=critical server2"
            rlRun -s "x509DumpCert server2"
            rlAssertGrep "OCSP No Check: critical" "$rlRun_LOG"
            rlRun "rm $rlRun_LOG"
        fi
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
        rlRun "x509RmAlias server2"
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
            )
        if ! rlIsRHEL 4; then
            options=(${options[@]} '--subjectAltName' 'IP.2=::1')
        fi
        rlRun "x509CertSign --CA ca --DN 'O=Test' ${options[*]} server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "Subject Alternative Name.*critical" "$rlRun_LOG"
        rlAssertGrep "example[.]com" "$rlRun_LOG"
        rlAssertGrep "localhost" "$rlRun_LOG"
        rlAssertGrep "192[.]168[.]0[.]1" "$rlRun_LOG"
        if ! rlIsRHEL 4; then
            rlAssertGrep "0:0:0:0:0:0:0:1" "$rlRun_LOG"
        fi
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

    # named constraints are not supported with RHEL-4 openssl
    if ! rlIsRHEL '<5'; then
    rlPhaseStartTest "nameConstraints"
_ncGet () { # helper function for extracting nameConstraints from certificates
    which=$1
    name=$2
    sed_cmd="ERROR"
    if [[ $which = "permitted" ]]; then
        sed_cmd='/Permitted:/,/Excluded/ p'
    elif [[ $which = "excluded" ]]; then
        sed_cmd='/Excluded:/,/Signature/ p'
    else
        sed_cmd="ERROR"
    fi
    x509DumpCert $name |sed -n "$sed_cmd"
}

        # basic sanity scenarios
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        # one permitted
        options=('--ncPermit' 'good.com')
        rlRun "x509SelfSign ${options[*]} ca"
        rlRun "x509CertSign --CA ca ${options[*]} server"
        rlRun "_ncGet permitted ca |grep good.com"
        rlRun "_ncGet permitted server |grep good.com"
        # one excluded
        options=('--ncExclude' 'bad.com')
        rlRun "x509SelfSign ${options[*]} ca"
        rlRun "x509CertSign --CA ca ${options[*]} server"
        rlRun "_ncGet excluded ca |grep bad.com"
        rlRun "_ncGet excluded server |grep bad.com"
        # one permitted and one excluded
        options=(
            '--ncPermit' 'good.com'
            '--ncExclude' 'bad.com'
            )
        rlRun "x509SelfSign ${options[*]} ca"
        rlRun "x509CertSign --CA ca ${options[*]} server"
        rlRun "_ncGet permitted ca |grep good.com"
        rlRun "_ncGet permitted server |grep good.com"
        rlRun "_ncGet excluded ca |grep bad.com"
        rlRun "_ncGet excluded server |grep bad.com"
        # multiple permitted
        options=(
            '--ncPermit' 'good1.com'
            '--ncPermit' 'good2.com'
            )
        rlRun "x509SelfSign ${options[*]} ca"
        rlRun "x509CertSign --CA ca ${options[*]} server"
        rlRun "_ncGet permitted ca |grep good1.com"
        rlRun "_ncGet permitted ca |grep good2.com"
        rlRun "_ncGet permitted server |grep good1.com"
        rlRun "_ncGet permitted server |grep good2.com"
        # multiple excluded
        options=(
            '--ncExclude' 'bad1.com'
            '--ncExclude' 'bad2.com'
            )
        rlRun "x509SelfSign ${options[*]} ca"
        rlRun "x509CertSign --CA ca ${options[*]} server"
        rlRun "_ncGet excluded ca |grep bad1.com"
        rlRun "_ncGet excluded ca |grep bad2.com"
        rlRun "_ncGet excluded server |grep bad1.com"
        rlRun "_ncGet excluded server |grep bad2.com"
        # cleanup
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"

        # complex scenario
        rlRun "x509KeyGen rootca"
        options=(
            '--ncPermit' 'DNS:example.com'
            '--ncExclude' 'DNS:bad.example.com'
            '--ncExclude' 'DNS:worse.example.com'
            )
        rlRun "x509SelfSign ${options[*]} rootca"
        rlRun -s "x509DumpCert rootca |sed -n '/Permitted:/,/Excluded/ p'"
        rlAssertGrep "^[[:space:]]*DNS:example.com" "$rlRun_LOG"
        rm -f "$rlRun_LOG"
        rlRun -s "x509DumpCert rootca |sed -n '/Excluded:/,/Signature/ p'"
        rlAssertGrep "^[[:space:]]*DNS:bad.example.com" "$rlRun_LOG"
        rlAssertGrep "^[[:space:]]*DNS:worse.example.com" "$rlRun_LOG"
        rm -f "$rlRun_LOG"
        rlRun "x509KeyGen interca"
        options=(
            '--CA' 'rootca'
            '-t' 'ca'
            '--subjectAltName' 'DNS.1=ca.sub.example.com'
            '--ncPermit' 'DNS:sub.example.com'
            '--ncExclude' 'DNS:bad.sub.example.com'
            )
        rlRun "x509CertSign ${options[*]} interca"
        rlRun -s "x509DumpCert interca |sed -n '/Permitted:/,/Excluded/ p'"
        rlAssertGrep "^[[:space:]]*DNS:sub.example.com" "$rlRun_LOG"
        rm -f "$rlRun_LOG"
        rlRun -s "x509DumpCert interca |sed -n '/Excluded:/,/Signature/ p'"
        rlAssertGrep "^[[:space:]]*DNS:bad.sub.example.com" "$rlRun_LOG"
        rm -f "$rlRun_LOG"
        rlRun "x509KeyGen server"
        for t in www.sub.example.com:0 bad.example.com:2 bad.sub.example.com:2; do
            server=${t%:*}
            expected=${t#*:}
            options=(
                '--CA' 'interca'
                '--subjectAltName' "DNS.1=$server"
                '--DN' "CN=$server"
                '--noAuthKeyId'
                )
            rlRun "x509CertSign ${options[*]} server"
            options=(
                '-trusted' "$(x509Cert rootca)"
                '-untrusted' "$(x509Cert interca)"
                )
            if rlIsRHEL '<6'; then
                # RHEL-5 openssl does not know about name constraints
                rlRun -s "openssl verify ${options[*]} $(x509Cert server)" 0
                rlAssertGrep "^error.*unhandled critical extension" $rlRun_LOG
                rm -f $rlRun_LOG
            elif rlIsRHEL 6 && rlIsRHEL '<6.5' && [[ $expected -eq 2 ]]; then
                # workaround for older RHEL-6, different return values of verify
                rlRun -s "openssl verify ${options[*]} $(x509Cert server)" 0
                rlAssertGrep "^error.*lookup:excluded subtree violation" $rlRun_LOG
                rm -f $rlRun_LOG
            else
                rlRun "openssl verify ${options[*]} $(x509Cert server)" $expected
            fi
        done
        rlRun "x509RmAlias rootca"
        rlRun "x509RmAlias interca"
        rlRun "x509RmAlias server"
    rlPhaseEnd
    fi

    rlPhaseStartTest "Certificate Revocation"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        rlRun -s "x509Revoke --CA ca server"
        rlAssertGrep "Revoking Certificate 02" "$rlRun_LOG"
        rlRun -s "openssl ca -status 2 -config ca/$x509CACNF" 1
        rlAssertGrep "02=Revoked" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "CRL reason"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        rlRun "x509Revoke --CA ca --crlReason cessationOfOperation server"
        rlAssertGrep '^R.*cessationOfOperation.*02.*$' "ca/$x509CAINDEX"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "CRL Compromise Time"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        now="$(date +"%Y%m%d%H%M%S%z")"
        rlRun "x509Revoke --CA ca --crlCompromiseTime $now server"
        expected="^R.*keyTime,$now.*02.*$"
        rlAssertGrep "$expected" "ca/$x509CAINDEX"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "CRL CA Compromise Time"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        now="$(date +"%Y%m%d%H%M%S%z")"
        rlRun "x509Revoke --CA ca --crlCACompromiseTime $now server"
        expected="^R.*CAkeyTime,$now.*02.*$"
        rlAssertGrep "$expected" "ca/$x509CAINDEX"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "Generate CRL"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca server"
        rlRun -s "x509Revoke --CA ca server"
        rlAssertGrep "Revoking Certificate 02" "$rlRun_LOG"
        rlRun "x509GenerateCRL ca"
        rlAssertExists "ca/$x509CRL"
        rlRun -s "openssl crl -in ca/$x509CRL -text"
        rlAssertGrep "Certificate Revocation List" "$rlRun_LOG"
        rlAssertGrep "Revoked Certificates" "$rlRun_LOG"
        rlAssertGrep "Serial Number: 02" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartTest "CRL next update days and hours"
        rlRun "x509KeyGen ca"
        rlRun "x509SelfSign ca"

        # Set due date to 1 day from now
        rlRun "x509GenerateCRL ca --crlDays 1"
        rlAssertExists "ca/$x509CRL"
        rlRun -s "openssl crl -in ca/$x509CRL -text"
        rlAssertGrep "Certificate Revocation List" "$rlRun_LOG"
        # calculate expected "next update"
        last=$(grep "Last Update:" "$rlRun_LOG" |
                     sed -E 's/^.*Last Update: //')
        next=$(date -d "$(grep "Next Update:" "$rlRun_LOG" |
                          sed -E 's/^.*Next Update: //')" +'%s')
        expected=$(date -d "$last + 1 day" +"%s")
        rlAssertEquals 'Check for expected next update' "$next" "$expected"

        rlRun "rm $rlRun_LOG"

        # Set due date to 1 hour from now
        rlRun "x509GenerateCRL ca --crlHours 1"
        rlAssertExists "ca/$x509CRL"
        rlRun -s "openssl crl -in ca/$x509CRL -text"
        rlAssertGrep "Certificate Revocation List" "$rlRun_LOG"
        # calculate expected "next update"
        last=$(grep "Last Update:" "$rlRun_LOG" |
                     sed -E 's/Last Update: //')
        next=$(date -d "$(grep "Next Update:" "$rlRun_LOG" |
                          sed -E 's/^.*Next Update: //')" +'%s')
        expected=$(date -d "$last + 1 hour" +"%s")
        rlAssertEquals 'Check for expected next update' "$next" "$expected"

        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
    rlPhaseEnd

    rlPhaseStartTest "CRL Distribution Points extension"
        rlRun "x509KeyGen ca"
        rlRun "x509KeyGen server"
        rlRun "x509SelfSign ca"
        rlRun "x509CertSign --CA ca --crlDistributionPoints https://crl.example.com server"
        rlRun -s "x509DumpCert server"
        rlAssertGrep "CRL Distribution Points" "$rlRun_LOG"
        rlAssertGrep "crl[.]example[.]com" "$rlRun_LOG"
        rlRun "rm $rlRun_LOG"
        rlRun "x509RmAlias ca"
        rlRun "x509RmAlias server"
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
