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

=item B<x509FORMAT>

Formatting required by the I<openssl> tool for generating certificates.
For RHEL6 and later it should be set to C<+%Y%m%d%H%M%SZ>.
For RHEL5 it should be set to C<+%y%m%d%H%M%SZ>.

Defaults to the RHEL6 and RHEL7 compatible setting.

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
x509CASERIAL=${x509CASERIAL:-serial}
x509FORMAT=${x509FORMAT:-+%Y%m%d%H%M%SZ}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Internal Functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

__INTERNAL_x509GenConfig() {

    # variable that has the DN broken up by items, most significant first
    local dn=()
    # hash used to sign the certificate
    local md="sha256"
    # current time in seconds from UNIX epoch
    local now=$(date '+%s')
    # date before which the certificate is not valid
    local notBefore=""
    # date after which the certificate is not valid
    local notAfter=""
    # Basic Key Usage to set
    local basicKeyUsage=""
    # Basic Constraints to set
    local basicConstraints=""
    # whatever to generate Subject Key Identifier extension
    local subjectKeyIdentifier=""
    # whatever to generate Authority Key Identifier extension
    local authorityKeyIdentifier=""
    # variable that has the Subject Alternative Name split by lines
    local subjectAltName=()
    # variable to store Authority Info Access (OCSP responder and CA file loc.)
    local authorityInfoAccess=()
    # value of the Extended Key Usage extension
    local extendedKeyUsage=""
    # list of all the arbitrary X509v3 extensions
    local x509v3Extension=()

    #
    # parse options
    #

    local TEMP=$(getopt -o t: -l dn: -l md: -l notBefore: -l notAfter: \
        -l basicKeyUsage: \
        -l basicConstraints: \
        -l subjectKeyIdentifier \
        -l authorityKeyIdentifier \
        -l subjectAltName: \
        -l authorityInfoAccess: \
        -l extendedKeyUsage: \
        -l x509v3Extension: \
        -n x509GenConfig -- "$@")
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
            --notBefore) notBefore="$2"; shift 2
                ;;
            --notAfter) notAfter="$2"; shift 2
                ;;
            --basicKeyUsage) basicKeyUsage="$2"; shift 2
                ;;
            --basicConstraints) basicConstraints="$2"; shift 2
                ;;
            --subjectKeyIdentifier) subjectKeyIdentifier="true"; shift 1
                ;;
            --authorityKeyIdentifier) authorityKeyIdentifier="true"; shift 1
                ;;
            --subjectAltName) subjectAltName+=("$2"); shift 2
                ;;
            --authorityInfoAccess) authorityInfoAccess+=("$2"); shift 2
                ;;
            --extendedKeyUsage) extendedKeyUsage="$2"; shift 2
                ;;
            --x509v3Extension) x509v3Extension="$2"; shift 2
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
    # process options
    #

    if [ -z "$notBefore" ]; then
        notBefore="now"
    fi
    notBefore=$(date -d "$notBefore" -u $x509FORMAT)
    if [ $? -ne 0 ]; then
        echo "x509GenConfig: notBefore date value is invalid" >&2
        return 1
    fi

    if [ -z "$notAfter" ]; then
        notAfter="1 year"
    fi
    notAfter=$(date -d "$notAfter" -u $x509FORMAT)
    if [ $? -ne 0 ]; then
        echo "x509GenConfig: notAfter date value is invalid" >&2
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
oid_section = new_oids

[ new_oids ]
ocspSigning = 1.3.6.1.5.5.7.3.9
ocspNoCheck = 1.3.6.1.5.5.7.48.1.5

[ ca ]
default_ca = ca_cnf

[ ca_cnf ]
default_md = $md
default_startdate = $notBefore
default_enddate   = $notAfter
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

    cat >> "$kAlias/$x509CACNF" <<EOF

[ v3_ext ]
EOF

    if [[ ! -z $basicConstraints ]]; then
        echo "basicConstraints =$basicConstraints" >> "$kAlias/$x509CACNF"
    fi

    if [[ ! -z $basicKeyUsage ]]; then
        echo "keyUsage =$basicKeyUsage" >> "$kAlias/$x509CACNF"
    fi

    if [[ ! -z $extendedKeyUsage ]]; then
        echo "extendedKeyUsage =$extendedKeyUsage" >> "$kAlias/$x509CACNF"
    fi

    if [[ ! -z $subjectKeyIdentifier ]]; then
        echo "subjectKeyIdentifier=hash" >> "$kAlias/$x509CACNF"
    fi

    if [[ ! -z $authorityKeyIdentifier ]]; then
        echo "authorityKeyIdentifier=keyid" >> "$kAlias/$x509CACNF"
    fi

    if [[ ${#subjectAltName[@]} -ne 0 ]]; then
        echo "subjectAltName = @alt_name" >> "$kAlias/$x509CACNF"
    fi

    if [[ ${#authorityInfoAccess[@]} -ne 0 ]]; then
        local aia_val=""
        local separator=""
        for aia in "${authorityInfoAccess[@]}"; do
            aia_val+="${separator}${aia}"
            separator=","
        done
        echo "authorityInfoAccess = $aia_val" >> "$kAlias/$x509CACNF"
    fi

    local ext
    for ext in "${x509v3Extension[@]}"; do
        echo "$ext" >> "$kAlias/$x509CACNF"
    done

    # subject alternative name section

    if [[ ${#subjectAltName[@]} -ne 0 ]]; then
        echo "" >> "$kAlias/$x509CACNF"
        echo "[ alt_name ]" >> "$kAlias/$x509CACNF"

        for name in "${subjectAltName[@]}"; do
            echo "$name" >> "$kAlias/$x509CACNF"
        done
    fi

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
[B<--basicKeyUsage> I<BASICKEYUSAGE>]
[B<--bcCritical>]
[B<--bcPathLen> I<LENGTH>]
[B<--caFalse>]
[B<--caTrue>]
[B<--CN> I<commonName>]
[B<--DN> I<part-of-dn>]
[B<--md> I<HASH>]
[B<--noBasicConstraints>]
[B<--notAfter> I<ENDDATE>]
[B<--notBefore> I<STARTDATE>]
[B<-t> I<type>]
[B<-v> I<version>]
I<alias>

=back

=over

=item B<--basicKeyUsage> I<BASICKEYUSAGE>

Specified the value of X.509 version 3 Basic Key Usage extension.

See B<X.509 EXTENSIONS> section for avaliable values for I<BASICKEYUSAGE>.
In case the value should be marked critical, prepend the values with
C<critical,>.

Default value for role C<ca> is C<critical, keyCertSign, cRLSign>.
For role C<webserver> is
C<critical, digitalSignature, keyEncipherment, keyAgreement>.
For role C<webclient> is C<digitalSignature, keyEncipherment>.

=item B<--bcCritical>

Sets the C<critical> flag for Basic Constraints extension.

=item B<--bcPathLen> I<LENGTH>

Sets the maximum path len for certificate chain to I<LENGTH>.

Undefined (unbounded) by default.

=item B<--caFalse>

Sets the Basic Constraints flag for CA to false. Note that this unsets the
default criticality flag for Basic Constraints. To restore it, use
B<--bcCritical>.

=item B<--caTrue>

Sets the Basic Constraints flag for CA to true. Note that this unsets
the flag for criticality of Basic Constraints. To restore it, use
B<--bcCritical>.

This is the default for C<CA> role together with B<--bcCritical>

=item B<--CN> I<commonName>

Specifies the common name (CN) for distinguished name (DN) in the certificate.
This applies for both the subject name and issuer name in the generated
certificate.

If no B<--DN>'s are specified, C<localhost> will be used for I<webserver> and
C<John Smith> for I<webclient>. I<ca> role will not get a common name but
its DN will be set to C<O=Example CA>.

=item B<--DN> I<part-of-dn>

Specifies parts of distinguished name (DN) of the generated certificate.
The order will be the same as will appear in the certificate.
If the B<--CN> option is also specified then I<commonName> will be placed last.

The I<part-of-dn> is comprised of two values with C<=> in the middle.
For example: C<commonName = example.com>, C<OU=Example Unit> or C<C=US>.

Note that existence of no particular element is enforced but the DN I<must>
have at least one element. If none is specified, the defaults from B<--CN>
option will be used.

Note that the case in DN elements B<is> significant.

TODO: Insert list of known DN parts

=over

=item I<CN> | I<commonName>

Human readable name

=item I<OU> | I<organisationalUnit>

Name of company department

=item I<O> | I<organisationName>

Name of organisation or company

=item I<C> | I<countryName>

Two letter code of country

=item I<emailAddress>

RFC822 address

=item I<localityName>

City name

=item I<stateOrProvinceName>

State or province name hosting the HQ.

=back

=item B<--md> I<HASH>

Sets the cryptographic hash (message digest) for signing certificates.

Note that some combinations of key types and digest algorithms are unsupported.
For example, you can't sign using ECDSA and MD5.

SHA256 by default, will be updated to weakeast hash recommended by NIST or
generally thought to be secure.

=item B<--noBasicConstraints>

Remove Basic Constraints extension from the certificate completely.
Note that in PKIX certificate validation, V3 certificate with no Basic
Constraints will I<not> be considered to be a CA.

=item B<--notAfter> I<ENDDATE>

Sets the date after which the certificate won't be valid.
Uses date(1) for conversion so values like "1 year" (from now), "2 years ago",
"3 months", "4 weeks ago", "2 days ago", etc. work just as well as values
like "20100101123500Z".
Use C<date -d I<ENDDATE>> to verify if it represent the date you want.

By default C<10 years> for I<ca> role, C<1 year> for all others.

=item B<--notBefore> I<STARTDATE>

Sets the date since which the certificate is valid. Uses date(1) for conversion
so values like "1 year" (from now), "2 years ago", "3 months", "4 weeks ago",
"2 days ago", etc. work just as well as values like "20100101123500Z".
Use C<date -d I<STARTDATE>> to verify if it represents the date you want.

By default C<5 years ago> for I<ca> role, C<now> for all others.

=item B<-t> I<type>

Sets the general type of certificate: C<CA>, C<webserver> or C<webclient>.
In case there are no additional options, this also sets correct values
for basic key usage and extended key usage for given role.

Note that while the names indicate "web", they actually apply for all servers
and clients that use TLS or SSL and in case of C<webclient> also for S/MIME.

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
    # date since which the cert is valid
    local notBefore=""
    # date until which the cert is valid
    local notAfter=""
    # value for Basic Key Usage Extension
    local basicKeyUsage=""
    # set the value for CA bit for Basic Constraints
    local basicConstraints=""
    # set the length for pathlen in Basic Constraints
    local bcPathLen=""
    # set the criticality flag for Basic Constraints
    local bcCritical=""
    # set the message digest algorithm used for signing
    local certMD=""

    #
    # parse options
    #

    local TEMP=$(getopt -o t:v: -l CN: -l DN: -l notAfter: -l notBefore \
        -l basicKeyUsage: \
        -l caTrue \
        -l caFalse \
        -l noBasicConstraints \
        -l bcPathLen: \
        -l bcCritical \
        -l md: \
        -n x509SelfSign -- "$@")
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
            --notAfter) notAfter="$2"; shift 2
                ;;
            --notBefore) notBefore="$2"; shift 2
                ;;
            --basicKeyUsage) basicKeyUsage="$2"; shift 2
                ;;
            --caTrue) basicConstraints="CA:TRUE"; shift 1
                ;;
            --caFalse) basicConstraints="CA:FALSE"; shift 1
                ;;
            --noBasicConstraints) basicConstraints="undefined"; shift 1
                ;;
            --bcPathLen) bcPathLen="$2"; shift 2
                ;;
            --bcCritical) bcCritical="true"; shift 1
                ;;
            --md) certMD="$2"; shift 2
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
        echo "x509SelfSign: private key '$kAlias' has not yet been generated"\
            >&2
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

    if [[ $certV == 1 ]]; then
        if [[ ! -z $basicKeyUsage ]]; then
            echo "x509SelfSign: Can't create version 1 certificate with "\
                "extensions" >&2
            return 1
        fi
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

    if [[ -z $notAfter ]] && [[ $certRole == "ca" ]]; then
        notAfter="10 years"
    fi # default of "1 year" is in config generator

    if [[ -z $notBefore ]] && [[ $certRole == "ca" ]]; then
        notBefore="5 years ago"
    fi # dafault of "now" is in config generator

    if [[ ! -z $bcPathLen ]]; then
        if [[ $basicConstraints == "undefined" ]] ||
            [[ $basicConstraints == "CA:FALSE" ]]; then
            echo "x509SelfSign: Path len can be specified only with caTrue "\
                "option" >&2
            return 1
        fi
        if [[ $certRole != "ca" ]] && [[ -z $basicConstraints ]]; then
            echo "x509SelfSign: Only ca role uses CA:TRUE constraint, use "\
                "--caTrue to override" >&2
            return 1;
        fi
    fi

    if [[ -z $basicConstraints ]]; then
        case $certRole in
            ca) basicConstraints="CA:TRUE"
                bcCritical="true"
                ;;
            *) basicConstraints="CA:FALSE"
                bcCritical="true"
                ;;
        esac
    fi

    local basicConstraintsOption=""
    if [[ $bcCritical == "true" ]]; then
        basicConstraintsOption="critical, "
    fi
    if [[ $basicConstraints == "undefined" ]]; then
        basicConstraintsOption=""
    else
        basicConstraintsOption+="${basicConstraints}"
        if [[ ! -z $bcPathLen ]]; then
            basicConstraintsOption+=", pathlen: ${bcPathLen}"
        fi
    fi

    if [[ -z $basicKeyUsage ]]; then
        case $certRole in
            ca) basicKeyUsage="critical, keyCertSign, cRLSign"
                ;;
            webserver) basicKeyUsage="critical, digitalSignature, "
                basicKeyUsage+="keyEncipherment, keyAgreement"
                ;;
            webclient) basicKeyUsage="digitalSignature, keyEncipherment"
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

    if [[ ! -z $notAfter ]]; then
        parameters+=("--notAfter=$notAfter")
    fi
    if [[ ! -z $notBefore ]]; then
        parameters+=("--notBefore=$notBefore")
    fi

    if [[ ! -z $basicConstraintsOption ]]; then
        parameters+=("--basicConstraints=$basicConstraintsOption")
    fi

    if [[ ! -z $basicKeyUsage ]]; then
        parameters+=("--basicKeyUsage=$basicKeyUsage")
    fi

    if [[ ! -z $certMD ]]; then
        parameters+=("--md=$certMD")
    fi

    # it will be included only in V3 certs, so we can add it by default
    parameters+=("--subjectKeyIdentifier")

    __INTERNAL_x509GenConfig "${parameters[@]}" "$kAlias"
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
        -batch -config $kAlias/$x509CACNF
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

    local caOptions=()
    caOptions+=("-preserveDN")
    if [[ $certV == "3" ]]; then
        caOptions+=("-extensions" "v3_ext")
    fi

    # finally sign the certificate using the full CA functionality
    openssl ca -config $kAlias/$x509CACNF -batch -keyfile $kAlias/$x509PKEY \
        -cert $kAlias/temp-$x509CERT -in $kAlias/$x509CSR \
        -out $kAlias/$x509CERT "${caOptions[@]}"
    if [ $? -ne 0 ]; then
        echo "x509SelfSign: signing the certificate failed" >&2
        return 1
    fi

}

true <<'=cut'
=pod

=head2 x509KeyCopy()

Create a new key by copying the key material from a different certificate/key.

=over 4

B<x509KeyCopy>
B<-t> I<target>
I<alias>

=back

Uses the key from I<alias> to create a directory I<target> with the same key.

Returns non zero if I<target> exists or I<alias> doesn't exist or doesn't
contain private key.

=cut

x509KeyCopy() {

    # destination of copy
    local newKey=""
    # source of key
    local kAlias=""

    local TEMP=$(getopt -o t: -n x509KeyCopy -- "$@")
    if [ $? -ne 0 ]; then
        echo "X509KeyCopy: Can't parse options" >&2
        return 1
    fi

    eval set -- "$TEMP"

    while true ; do
        case "$1" in
            -t) newKey="$2"; shift 2
                ;;
            --) shift 1
                break
                ;;
            *) echo "x509KeyCopy: Unknown option: $1" >&2
                return 1
        esac
    done

    kAlias="$1"

    if [ ! -e "$kAlias/$x509PKEY" ]; then
        echo "x509KeyCopy: Source invalid" >&2
        return 1
    fi

    if [ -e "$newKey" ]; then
        echo "x509KeyCopy: Destination exists" >&2
        return 1
    fi

    mkdir "$newKey"
    if [ $? -ne 0 ]; then
        echo "x509KeyCopy: Can't create directory for new key" >&2
        return 1
    fi

    cp "$kAlias/$x509PKEY" "$newKey"
    if [ $? -ne 0 ]; then
        echo "x509KeyCopy: Can't copy key" >&2
        return 1
    fi

    return 0
}

true <<'=cut'
=pod

=head2 x509CertSign()

Create a certificate signed by a given alias.

=over 4

B<x509CertSign>
[B<--bcCritical>]
[B<--bcPathLen> I<PATHLEN>]
[B<--caFalse>]
[B<--caTrue>]
[B<--DN> I<DNPART>]
[B<--extendedKeyUsage> I<EKU>]
[B<--md> I<HASHNAME>]
[B<--noBasicConstraints>]
[B<--notAfter> I<ENDDATE>]
[B<--notBefore> I<STARTDATE>]
[B<--ocspNoCheck> [I<CRITICAL>]]
[B<--ocspResponderURI> I<URI>]
[B<--subjectAltName> I<ALTNAME>]
[B<-t> I<TYPE>]
[B<-v> I<version>]
B<--CA> I<CAAlias>
I<alias>

=back

=over

=item B<--bcCritical>

Sets the C<critical> flag for Basic Constraints extension.
See B<X.509 EXTENSIONS> section to see what it means.

=item B<--bcPathLen> I<PATHLEN>

Sets the maximum path len for certificate chain to I<PATHLEN>.

Undefined (unbounded) by default.

=item B<--CA> I<CAAlias>

Name the key and certificate used for signing the new certificate.

The CA specified by I<CAAlias> must have its key generated and certificate
present (either through self signing or through previous certificate
signing operation).

=item B<--caFalse>

Sets the Basic Constraints flag for CA to false. Note that his unsets the
default criticality flag for Basic Constraints. To restore it, use
B<--bcCritical>.

This is the default for C<webserver> and C<webclient> roles.

=item B<--caTrue>

Sets the Basic Constraints flag for CA to true. Note that this unsets
the default flag for criticality of Basic Constraints. To restore it, use
B<--bcCritical>.

This is the default for C<CA> role.

=item B<--DN> I<DNPART>

Specifies parts of distinguished name (DN) of the generated certificate.
The order in which they are provided will be used for certificate generation.

See the same option description for I<x509SelfSign> for available I<DNPART>
options.

By default C<O = Example intermediate CA> for C<CA> role, C<CN = localhost>
for C<webserver> role and C<CN = John Smith> for C<webclient> role.

=item B<--extendedKeyUsage> I<EKU>

Add the Extended Key Usage extension to the certificate. I<EKU> is a comma
separated list of key usages. Both literal OIDs and names can be used.

Define as empty string to remove the default value. Prepend C<critical,> before
usage names to mark the extension as critical.

Valid names are:

=over

=item I<serverAuth>

SSL/TLS Server authentication

=item I<clientAuth>

SSL/TLS Client authentication

=item I<codeSigning>

Executable code signing

=item I<emailProtection>

Signing and encrypting S/MIME messages.

=item I<timeStamping>

Signing of trusted timestamps (required for Time Stamping Authority),
many implementations require this use to be only one and marked as critical
for the TSA to be considered valid.

=item I<msCodeInd>

Microsoft Individual Code Signing (authnticode)

=item I<msCodeCom>

Microsoft Commercial Code Signing (authenticode)

=item I<msCTLSign>

Microsoft Trust List signing

=item I<msSGC>

Microsoft Server Gated Cryptography

=item I<msEFS>

Microsoft Encrypted File System

=item I<nsSGC>

Netscape Server Gated Crypto

=item I<ocspSigning>

Allow the server to sign OCSP responses, also known as id_kp_OCSPSigning.

=back

By default undefined for C<CA> role, I<serverAuth> for C<webserver> role and
I<clientAuth,emailProtection> for C<webclient>.

=item B<--md> I<HASHNAME>

Sets the cryptographic hash (message digest) for signing certificates.

Note that some combinations of key types and digest algorithms are unsupported.
For example, you can't sign using ECDSA and MD5.

SHA256 by default, will be updated to weakeast hash recommended by NIST or
generally thought to be secure.

=item B<--noAuthKeyId>

Do not add the Authority Key Identifier extension to generated certificates.

=item B<--noBasicConstraints>

Remove Basic Constraints extension from the certificate completely.
Note that in PKIX certificate validation, V3 certificate with no Basic
Constraints will I<not> be considered to be a CA.

=item B<--noSubjKeyId>

Do not add the Subject Key Identifier extension to generated certificates.

=item B<--notAfter> I<ENDDATE>

Sets the date after which the certificate won't be valid.
Uses date(1) for conversion so values like "1 year" (from now), "2 years ago",
"3 months", "4 weeks ago", "2 days ago", etc. work just as well as values
like "20100101123500Z".
Use C<date -d I<ENDDATE>> to verify if it represent the date you want.

By default C<10 years> for I<ca> role, C<1 year> for all others.

=item B<--notBefore> I<STARTDATE>

Sets the date since which the certificate is valid. Uses date(1) for conversion
so values like "1 year" (from now), "2 years ago", "3 months", "4 weeks ago",
"2 days ago", etc. work just as well as values like "20100101123500Z".
Use C<date -d I<STARTDATE>> to verify if it represents the date you want.

By default C<5 years ago> for I<ca> role, C<now> for all others.

=item B<--ocspNoCheck> [I<CRITICAL>]

Add the OCSP No Check extension to certificate, also known as
id-pkix-ocsp-nocheck.

I<CRITICAL> is the optional argument that, if provided (with any value, though
C<critical> is recommended), will mark the extension as critical.

=item B<--ocspResponderURI> I<URI>

Add Authority Info Access extension that specifies location of the OCSP
responder fo this certificate. The URI must be specified with protocol.

For example:

    http://ocsp.example.com/

=item B<--subjectAltName> I<ALTNAME>

Specify the Subject Alternative Name extension items to add. The format is
similar to the B<DN>, first the literal added, then equals sign (=) and
finally the value added.

The literals supported are:

=over

=item I<email>

Email address in the form:

    username@domainname

=item I<URI>

Full Uniform Resource Identifier, with protocol, host name and location.

=item I<DNS>

DNS host name

=item I<IP>

An IP Address, both IPv4 and IPv6 is supported

=back

Note that if you want multiple literals of the same type, you need to specify
the order in which they will be placed by appending position after a dot:

    DNS.1=example.com
    DNS.2=www.example.com

=item B<-t> I<TYPE>

Sets the general type of certificate: C<CA>, C<webserver> or C<webclient>.
In case there are no additional options, this also sets correct values
for basic key usage and extended key usage for given role.

Note that while the names indicate "web", they actually apply for all servers
and clients that use TLS or SSL and in case of C<webclient> also for S/MIME.

C<webserver> by default.

=item B<-v> I<version>

Version of the certificate to create, accepted versions are C<1> and C<3>.
Unfortunately, creating version C<1> certificate with extensions is impossible
with current openssl so the script detects that and returns error.

Version C<3> by default.

=item I<alias>

Location of the private key for signing.

Note that the private key must have been already generated.

=back

Return 0 if signing was successfull, non zero otherwise.

=cut

x509CertSign() {
    # alias of the key to be signed
    local kAlias
    # alias of the CA key and cert to be used for signing
    local caAlias
    # X.509 certificate version (1 or 3)
    local certV="3"
    # role of certificate
    local certRole="webserver"
    # date since which the cert is valid
    # default is in config generator (now)
    local notBefore=""
    # date until which the cert is valid
    # default is in config generator (1 year)
    local notAfter=""
    # set the value for CA bit for Basic Constraints
    local basicConstraints=""
    # set the length for pathlen in Basic Constraints
    local bcPathLen=""
    # set the criticality flag for Basic Constraints
    local bcCritical=""
    # set the message digest used for signing the certificate
    # default is in config generator (sha256)
    local certMD=""
    # sets the Basic Key Usage
    local basicKeyUsage=""
    # distinguished name of the signed certificate
    local certDN=()
    # Subject Alternative Name of the signed certificate
    local subjectAltName=()
    # location of OCSP responder for the CA that issued this certificate
    local ocspResponderURI=""
    # value for the Extended Key Usage extension
    local extendedKeyUsage=""
    # flag to set the ocsp nocheck extension
    local ocspNoCheck=""
    local noAuthKeyId=""
    local noSubjKeyId=""

    #
    # parse options
    #

    local TEMP=$(getopt -o v:t: -l CA: \
        -l notAfter: \
        -l notBefore: \
        -l caTrue \
        -l caFalse \
        -l noBasicConstraints \
        -l bcPathLen: \
        -l bcCritical \
        -l md: \
        -l subjectAltName: \
        -l ocspResponderURI: \
        -l extendedKeyUsage: \
        -l ocspNoCheck:: \
        -l noAuthKeyId \
        -l noSubjKeyId \
        -n x509CertSign -- "$@")
    if [ $? -ne 0 ]; then
        echo "x509CertSign: can't parse options" >&2
        return 1
    fi

    eval set -- "$TEMP"

    while true ; do
        case "$1" in
            -v) certV="$2"; shift 2
                ;;
            -t) certRole="$2"; shift 2
                ;;
            --CA) caAlias="$2"; shift 2
                ;;
            --notAfter) notAfter="$2"; shift 2
                ;;
            --notBefore) notBefore="$2"; shift 2
                ;;
            --caTrue) basicConstraints="CA:TRUE"; shift 1
                ;;
            --caFalse) basicConstraints="CA:FALSE"; shift 1
                ;;
            --noBasicConstraints) basicConstraints="undefined"; shift 1
                ;;
            --bcPathLen) bcPathLen="$2"; shift 2
                ;;
            --bcCritical) bcCritical="true"; shift 1
                ;;
            --md) certMD="$2"; shift 2
                ;;
            --subjectAltName) subjectAltName+=("$2"); shift 2
                ;;
            --ocspResponderURI) ocspResponderURI="$2"; shift 2
                ;;
            --extendedKeyUsage) extendedKeyUsage="$2"; shift 2
                ;;
            --ocspNoCheck) if [[ -z $2 ]]; then
                    ocspNoCheck="true"
                else
                    ocspNoCheck="critical"
                fi
                shift 2
                ;;
            --noAuthKeyId) noAuthKeyId="true"; shift 1
                ;;
            --noSubjKeyId) noSubjKeyId="true"; shift 1
                ;;
            --) shift 1
                break
                ;;
            *) echo "x509CertSign: Unknown option: $1" >&2
                return 1
        esac
    done

    kAlias="$1"

    #
    # sanity check options
    #

    if [ ! -e "$kAlias/$x509PKEY" ]; then
        echo "x509CertSign: Private key to be signed does not exist" >&2
        return 1
    fi

    if [ ! -e "$caAlias/$x509PKEY" ]; then
        echo "x509CertSign: CA private key does not exist" >&2
        return 1
    fi

    if [ ! -e "$caAlias/$x509CERT" ]; then
        echo "x509CertSign: CA certificate does not exist" >&2
        return 1
    fi

    if [[ $certV != "1" ]] && [[ $certV != "3" ]]; then
        echo "x509CertSign: Only version 1 and 3 certificates are supported" \
            >&2
        return 1
    fi

    certRole=${certRole,,}
    if [[ $certRole != "ca" ]] && [[ $certRole != "webserver" ]] \
        && [[ $certRole != "webclient" ]]; then

        echo "x509SelfSign: Unknown role: '$certRole'" >&2
        return 1
    fi

    if [ ${#certDN[@]} -eq 0 ]; then
        case $certRole in
            ca) certDN+=("O = Example intermediate CA")
                ;;
            webserver) certDN+=("CN = localhost")
                ;;
            webclient) certDN+=("CN = John Smith")
                ;;
            *) echo "x509CertSign: Unknown cert role: $certRole" >&2
                return 1
                ;;
        esac
    fi

    if [[ -z $notAfter ]] && [[ $certRole == "ca" ]]; then
        notAfter="10 years"
    fi # default of "1 year" for other roles is in config generator

    if [[ -z $notBefore ]] && [[ $certRole == "ca" ]]; then
        notBefore="5 years ago"
    fi # default of "now" for other roles is in config generator

    if [[ ! -z $bcPathLen ]]; then
        if [[ $basicConstraints == "undefined" ]] ||
            [[ $basicConstraints == "CA:FALSE" ]]; then
            echo "x509SelfSign: Path len can be specified only with caTrue "\
                "option" >&2
            return 1
        fi
        if [[ $certRole != "ca" ]] && [[ -z $basicConstraints ]]; then
            echo "x509SelfSign: Only ca role uses CA:TRUE constraint, use "\
                "--caTrue to override" >&2
            return 1;
        fi
    fi

    if [[ -z $basicConstraints ]]; then
        case $certRole in
            ca) basicConstraints="CA:TRUE"
                bcCritical="true"
                ;;
                # for other usages, the recommendation is to not define it at
                # all
        esac
    fi

    local basicConstraintsOption=""
    if [[ $bcCritical == "true" ]]; then
        basicConstraintsOption="critical, "
    fi
    if [[ $basicConstraints == "undefined" ]]; then
        basicConstraintsOption=""
    else
        basicConstraintsOption+="${basicConstraints}"
        if [[ ! -z $bcPathLen ]]; then
            basicConstraintsOption+=", pathlen: ${bcPathLen}"
        fi
    fi

    if [[ -z $basicKeyUsage ]]; then
        case $certRole in
            ca) basicKeyUsage="critical, keyCertSign, cRLSign"
                ;;
            webserver) basicKeyUsage="critical, digitalSignature, "
                basicKeyUsage+="keyEncipherment, keyAgreement"
                ;;
            webclient) basicKeyUsage="digitalSignature, keyEncipherment"
                ;;
            *) echo "x509SelfSign: Unknown cert role: $certRole" >&2
                return 1
                ;;
        esac
    fi

    if [[ -z $extendedKeyUsage ]]; then
        case $certRole in
            webserver) extendedKeyUsage="serverAuth"
                ;;
            webclient) extendedKeyUsage="clientAuth,emailProtection"
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

    if [[ ! -z $notAfter ]]; then
        parameters+=("--notAfter=$notAfter")
    fi
    if [[ ! -z $notBefore ]]; then
        parameters+=("--notBefore=$notBefore")
    fi

    if [[ ! -z $basicConstraintsOption ]]; then
        parameters+=("--basicConstraints=$basicConstraintsOption")
    fi

    if [[ ! -z $basicKeyUsage ]]; then
        parameters+=("--basicKeyUsage=$basicKeyUsage")
    fi

    if [[ ! -z $certMD ]]; then
        parameters+=("--md=$certMD")
    fi

    for name in "${subjectAltName[@]}"; do
        parameters+=("--subjectAltName=$name")
    done

    if [[ ! -z $ocspResponderURI ]]; then
        parameters+=("--authorityInfoAccess=OCSP;URI:${ocspResponderURI}")
    fi

    if [[ ! -z $extendedKeyUsage ]]; then
        parameters+=("--extendedKeyUsage=$extendedKeyUsage")
    fi

    if [[ $ocspNoCheck == "true" ]]; then
        parameters+=("--x509v3Extension=ocspNoCheck=DER:05:00")
    fi
    if [[ $ocspNoCheck == "critical" ]]; then
        parameters+=("--x509v3Extension=ocspNoCheck=critical,DER:05:00")
    fi

    if [[ $noSubjKeyId != "true" ]]; then
        parameters+=("--subjectKeyIdentifier")
    fi

    if [[ $noAuthKeyId != "true" ]]; then
        parameters+=("--authorityKeyIdentifier")
    fi

    __INTERNAL_x509GenConfig "${parameters[@]}" "$caAlias"
    if [ $? -ne 0 ]; then
        return 1
    fi

    #
    # create the certificate
    #

    openssl req -new -batch -key "$kAlias/$x509PKEY" -out "$kAlias/$x509CSR" \
        -config "$caAlias/$x509CACNF"
    if [ $? -ne 0 ]; then
        echo "x509CertSign: Certificate Signing Request generation failed" >&2
        return 1
    fi

    local caOptions=()
    caOptions+=("-preserveDN")
    if [[ $certV == "3" ]]; then
        caOptions+=("-extensions" "v3_ext")
    fi

    openssl ca -config "$caAlias/$x509CACNF" -batch \
        -keyfile "$caAlias/$x509PKEY" \
        -cert "$caAlias/$x509CERT" \
        -in "$kAlias/$x509CSR" \
        -out "$kAlias/$x509CERT" \
        "${caOptions[@]}"
    if [ $? -ne 0 ]; then
        echo "x509CertSign: Signing of the certificate failed" >&2
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
    local ret
    getopt -T
    ret=$?
    if [ ${ret} -ne 4 ]; then
        echo "certificate-generation: error: "\
            "Non GNU enhanced version of getopt" 1>&2
        return 1
    fi

    return 0
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Authors
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 X.509 EXTENSIONS

Version 3 certificates differ from version 1 certificates in that they can
be extended with arbitrary data.
Some of those exensions were standardised and can be used freely.

Note that extension marked as critical will cause certificate validation
failure if the validator does not know or understand the extension.
For common extensions like Basic Constraints or Key Usage it is highly
recommended to leave them critical, on the other hand, other types
of extensions should I<not> be marked as such.

Most important ones are:

=over

=item B<Basic Constraints>

Notifies certificate validator if the certificate is used by a Certification
Authority and how long can be the chain of intermediate certificates.

This extension should be marked as critical.

=item B<Basic Key Usage>

Sets how the certificate can be used with regards to low level cryptography
operations and basic PKI operations.

Full list includes:

=over

=item I<digitalSignature>

Signing hashed data. For example used for DHE and ECDHE suites.
I<Not> used for certificate or CRL signing.

=item I<nonRepudiation>

Proof of orgin and integrity of data, not used in TLS context.
I<Not> used for certificate or CRL signing.

=item I<keyEncipherment>

Encrypting keying material, used with RSA based TLS cipher suites.

=item I<dataEncipherment>

Encrypting data directly other than cryptographic keys.

=item I<keyAgreement>

Used when key is used for encryption key agreement. Used for DHE and ECDHE
cipher sutes.

=item I<keyCertSign>

Used for signing certificates. Note that the I<CA> bit in B<Basic Key Usage>
must also be set for this value to be effective.

=item I<cRLSign>

Used when signing CRL files. Not that the I<CA> bit in B<Basic Key Usage>
must also be set for this value to be effective.

=item I<encipherOnly>

Used together with I<keyAgreement> bit, marks the public key as usable only
for enciphering data when performing key agreement.

=item I<decipherOnly>

Used together with I<keyAgreement> bit, marks the public key as usable only
for deciphering data when performing key agreement.

=back

=back

=head1 AUTHORS

=over

=item *

Hubert Kario <hkario@redhat.com>

=back

=cut
