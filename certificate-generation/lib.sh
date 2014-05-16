#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   lib.sh of /CoreOS/openssl/Library/certificate-generation
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
#   library-prefix = x509
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 NAME

openssl/certificate-generation - Library for creating X.509 certificates for
any use

=head1 DESCRIPTION

This is a library aimed at making X.509 certificate creation simple without
sacrificing advanced functionality.

Typical use cases won't require any additional options and even complex
PKI structure for TLS can be created with just few commands.

Note that it assumes that all generated keys and certificates can be used as
CAs (even if they have extensions that specifically forbid it). Because of
that, every single key pair is placed in a separate directory named after its
alias.

This library uses I<getopt> for option parsing, as such the order of options
to functions is not significant unless noted.

=cut

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Variables
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 VARIABLES

Below is the list of global variables. If they are already defined in
environment when the library is loaded, they will NOT be overwritten.

=over

=item B<x509CACNF>

Name of the configuration file for CA operation and CSR generation.
F<ca.cnf> by default.

=item B<x509CAINDEX>

Name of the file with information about all the previously generated
certificates. F<index.txt> by default.

=item B<x509CASERIAL>

Name of the file with next available serial number. F<serial> by default.

=item B<x509CERT>

Name of file in which certificates will be placed. F<cert.pem> by default

=item B<x509CSR>

Name of the file with certificate signing request. F<request.csr> by default.

=item B<x509PKEY>

Name of file with private and public key. F<key.pem> by default

=back

Note that changing the values of above variables between running different
functions may cause the library to misbehave.

=cut

x509PKEY=${x509PKEY:-key.pem}
x509CERT=${x509CERT:-cert.pem}
x509CSR=${x509CSR:-request.csr}
x509CACNF=${x509CACNF:-ca.cnf}
x509CAINDEX=${x509CAINDEX:-index.txt}
x509CASERIAL=${X509CASERIAL:-serial}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Internal Functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

__INTERNAL_x509GenConfig() {

    # variable that has the DN broken up by items, most significant first
    local dn=()
    # hash used to sign the certificate
    local md="sha256"

    #
    # parse options
    #

    local TEMP=$(getopt -o t: -l dn: -l md: -n x509GenConfig -- "$@")
    if [ $? -ne 0 ]; then
        echo "x509GenConfig: can't parse options" >&2
        return 1
    fi

    eval set -- "$TEMP"

    while true ; do
        case "$1" in
            --dn) dn+=("$2"); shift 2
                ;;
            --md) md="$2"; shift 2
                ;;
            --) shift 1
                break
                ;;
            *) echo "x509GenConfig: Unknown option: \"$1\"" >&2
                return 1
        esac
    done

    local kAlias="$1"

    #
    # sanity check
    #

    if [ ! -e "$kAlias" ]; then
        echo "x509GenConfig: to gen config, the directory must be present" >&2
        return 1
    fi
    if [ ${#dn[@]} -lt 1 ]; then
        echo "x509GenConfig: at least one element in DN must be present" >&2
        return 1
    fi

    #
    # generate config
    #

    touch $kAlias/$x509CAINDEX
    if [ ! -e $kAlias/$x509CASERIAL ]; then
        echo 01 > $kAlias/$x509CASERIAL
    fi

    cat > "$kAlias/$x509CACNF" <<EOF
[ ca ]
default_ca = ca_cnf

[ ca_cnf ]
default_md = $md
default_startdate = 20100101120000Z
default_enddate   = 20200101120000Z
policy = policy_anything
preserveDN = yes
unique_subject = no
database = $kAlias/$x509CAINDEX
serial = $kAlias/$x509CASERIAL
new_certs_dir = $kAlias/

[ policy_anything ]
#countryName             = optional
#stateOrProvinceName     = optional
#localityName            = optional
#organizationName        = optional
#organizationalUnitName  = optional
commonName              = optional
#emailAddress            = optional

[ req ]
prompt = no
distinguished_name = cert_req

[ cert_req ]
EOF

    for item in "${dn[@]}"; do
        echo "$item" >> "$kAlias/$x509CACNF"
    done
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 FUNCTIONS

=head2 x509KeyGen()

Generate new key pair using given algorithm and key size.
By default it generates RSA key of the smallest size aceptable in FIPS mode
(currently 2048 bit).

=over 4

B<x509KeyGen>
[B<-t> I<type>]
[B<-s> I<size>]
I<alias>

=back

=over

=item B<-t> I<type>

Type of key pair to generate. Acceptable values are I<RSA> and I<DSA>. In
case the script is running on RHEL 6.5, RHEL 7.0, Fedora 19 or later, I<ECDSA>
is also supported.

I<RSA> by default.

=item B<-s> I<size>

Size of the used key for RSA and DSA. Name of the elliptic curve in case
of ECDSA key.

By default 2048 bit in case of RSA and DSA and C<prime256v1> in case of
ECDSA.

Other valid names for ECDSA curves can be acquired by running

    openssl ecparam -list_curves

=item I<alias>

Name of directory in which the generated key pair will be placed.
The file with key will be named F<key.pem> if the variable I<x509PKEY> was
not changed. If the directory does not exist it will be created. Please don't
put any files in it as they may be overwritten by running functions.

=back

Returns 0 if the key generation was successful. Non zero otherwise.

=cut

x509KeyGen() {

    # type of key to generate
    local kType="RSA"
    # size of key to generate
    local kSize=""
    # name of key to generate
    local kAlias

    #
    # parse options
    #

    local TEMP=$(getopt -o t:s: -n x509KeyGen -- "$@")
    if [ $? -ne 0 ]; then
        echo "x509KeyGen: can't parse options" >&2
        return 1
    fi

    eval set -- "$TEMP"

    while true ; do
        case "$1" in
            -t) kType="$2"; shift 2
                ;;
            -s) kSize="$2"; shift 2
                ;;
            --) shift 1
                break
                ;;
            *) echo "x509KeyGen: Unknown option: '$1'" >&2
                return 1
        esac
    done

    kAlias="$1"

    #
    # sanity check options
    #

    #upper case and lower case
    kType=${kType^^}
    kSize=${kSize,,}

    if [[ -z $kType ]]; then
        echo "x509KeyGen: Key type can't be empty" >&2
        return 1
    fi
    if [[ $kType != "RSA" ]] && [[ $kType != "DSA" ]] \
        && [[ $kType != "ECDSA" ]]; then

        echo "x509KeyGen: Unknown key type: $kType" >&2
        return 1
    fi
    if [[ -z $kSize ]]; then
        if [[ $kType == "ECDSA" ]]; then
            kSize="prime256v1"
        else
            kSize="2048"
        fi
    fi

    if [[ -z $kAlias ]]; then
        echo "x509KeyGen: No certificate alias specified" >&2
        return 1
    fi

    #
    # Generate the key
    #

    mkdir -p "$kAlias"

    if [[ $kType == "ECDSA" ]]; then
        openssl ecparam -genkey -name "$kSize" -out "$kAlias/$x509PKEY"
        if [ $? -ne 0 ]; then
            echo "x509KeyGen: Key generation failed" >&2
            return 1
        fi
    elif [[ $kType == "DSA" ]]; then
        openssl dsaparam "$kSize" -out "$kAlias/dsa$kSize.pem"
        if [ $? -ne 0 ]; then
            echo "x509KeyGen: Parameter generation failed" >&2
            return 1
        fi
        openssl gendsa -out "$kAlias/$x509PKEY" "$kAlias/dsa$kSize.pem"
        if [ $? -ne 0 ]; then
            echo "x509KeyGen: Key generation failed" >&2
            return 1
        fi
    else # RSA
        openssl genrsa -out "$kAlias/$x509PKEY" "$kSize"
        if [ $? -ne 0 ]; then
            echo "x509KeyGen: Key generation failed" >&2
        fi
    fi

}

true <<'=cut'
=pod

=head2 x509SelfSign()

Create a self signed certificate for a given alias.

=over 4

B<x509SelfSign>
[B<-v> I<version>]
[B<-t> I<type>]
[B<--CN> I<commonName>]
[B<--DN> I<part-of-dn>]
I<alias>

=back

=over

=item B<--CN> I<commonName>

Specifies the common name (CN) for distinguished name (DN) in the certificate.
This applies for both the subject name and issuer name in the generated
certificate.

If no B<--DN>'s are specified, C<localhost> will be used for I<webclient> and
C<John Smith> for I<webclient>. I<ca> role will not get a common name but
its DN will be set to C<O=Example CA>.

=item B<--DN> I<part-of-dn>

Specifies parts of distinguished name (DN) of the generated certificate.
The order will be the same as will appear in the certificate.
If the B<--CN> option is also specified then I<commonName> will be placed last.

The I<part-of-dn> is comprised of two values with C<=> in the middle.
For example: C<commonName = example.com>, C<OU=Example Unit> or C<C=US>.

TODO: Insert list of correct DNs

=item B<-t> I<type>

Sets the general type of certificate: C<CA>, C<webserver> or C<webclient>.
In case there are no additional options, this also sets correct values
for basic key usage and extended key usage for given role.

C<CA> by default.

=item B<-v> I<version>

Version of the certificate to create, accepted versions are C<1> and C<3>.
Unfortunately, creating version C<1> certificate with extensions is impossible
with current openssl so the script detects that and returns error.

Version C<3> by default.

=item I<alias>

Name of directory in which the generated certificate will be placed
and where the private key used for signing is located.
The certificate will be placed in file named F<cert.pem> if I<x509CERT>
variable was not changed.

=back

Returns 0 if signing was successfull, non zero otherwise.

=cut

x509SelfSign() {
    # name of key to process
    local kAlias
    # version of cert to generate
    local certV=3
    # role for certificate
    local certRole="CA"
    # common name of certificate
    local certCN
    # parts of DN (array)
    local certDN=()

    #
    # parse options
    #

    local TEMP=$(getopt -o t:v: -l CN: -l DN: -n x509SelfSign -- "$@")
    if [ $? -ne 0 ]; then
        echo "X509SelfSign: can't parse options" >&2
        return 1
    fi

    eval set -- "$TEMP"

    while true ; do
        case "$1" in
            -t) certRole="$2"; shift 2
                ;;
            -v) certV="$2"; shift 2
                ;;
            --CN) certCN="$2"; shift 2
                ;;
            --DN) certDN+=("$2"); shift 2
                ;;
            --) shift 1
                break
                ;;
            *) echo "x509SelfSign: Unknown option: '$1'" >&2
                return 1
        esac
    done

    kAlias="$1"

    #
    # sanity check options
    #

    if [ ! -d "$kAlias" ] || [ ! -e "$kAlias/$x509PKEY" ]; then
        echo "x509SelfSign: private key '$kAlias' has not yet been generated" >&2
        return 1
    fi

    certRole=${certRole,,}
    if [[ $certRole != "ca" ]] && [[ $certRole != "webserver" ]] \
        && [[ $certRole != "webclient" ]]; then

        echo "x509SelfSign: Unknown role: '$certRole'" >&2
        return 1
    fi

    if [[ $certV != 1 ]] && [[ $certV != 3 ]]; then
        echo "x509SelfSign: Certificate version must be 1 or 3" >&2
        return 1
    fi

    if [ ! -z "$certCN" ]; then
        certDN+=("CN = $certCN")
    fi

    if [ ${#certDN[@]} -eq 0 ]; then
        case $certRole in
            ca) certDN+=("O = Example CA")
                ;;
            webserver) certDN+=("CN = localhost")
                ;;
            webclient) certDN+=("CN = John Smith")
                ;;
            *) echo "x509SelfSign: Unknown cert role: $certRole" >&2
                return 1
                ;;
        esac
    fi

    #
    # prepare configuration file for signing
    #

    local parameters=()
    for option in "${certDN[@]}"; do
        parameters+=("--dn=$option")
    done

    __INTERNAL_x509GenConfig "${parameters[@]}" $kAlias
    if [ $? -ne 0 ]; then
        return 1
    fi

    #
    # create self signed certificate
    #

    # because we want to have full control over certificate fields
    # (like notBefore and notAfter) we have to create the certificate twice

    # create dummy self signed certificate
    openssl req -x509 -new -key $kAlias/$x509PKEY -out $kAlias/temp-$x509CERT \
        -batch -config $kAlias/$x509CACNF -subj "/OU=TEST/c=pl"
    if [ $? -ne 0 ]; then
        echo "x509SelfSign: temporary certificate generation failed" >&2
        return 1
    fi

    # create CSR for signing by the dummy certificate
    openssl x509 -x509toreq -signkey $kAlias/$x509PKEY -out $kAlias/$x509CSR \
        -in $kAlias/temp-$x509CERT
    if [ $? -ne 0 ]; then
        echo "x509SelfSign: certificate signing request failed" >&2
        return 1
    fi

    # finally sign the certificate using the full CA functionality
    openssl ca -config $kAlias/$x509CACNF -batch -keyfile $kAlias/$x509PKEY \
        -cert $kAlias/temp-$x509CERT -in $kAlias/$x509CSR \
        -out $kAlias/$x509CERT -preserveDN
    if [ $? -ne 0 ]; then
        echo "x509SelfSign: signing the certificate failed" >&2
        return 1
    fi

}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Execution
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 EXECUTION

This library works correctly only when sourced. I.e.:

    . ./lib.sh

=over

=back

=cut

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Verification
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   This is a verification callback which will be called by
#   rlImport after sourcing the library to make sure everything is
#   all right. The function should return 0 only when the library
#   is ready to serve.

x509LibraryLoaded() {
    local ret=0
    getopt -T || ret=$?
    if [ ${ret} -ne 4 ]; then
        echo "certificate-generation: error: old version of getopt" 1>&2
        return 1
    fi

    return 0
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Authors
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 AUTHORS

=over

=item *

Hubert Kario <hkario@redhat.com>

=back

=cut
