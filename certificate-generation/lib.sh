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

openssl/certificate-generation - Library for creating X.509 certificates for any use

=head1 DESCRIPTION

This is a library aimed at making X.509 certificate creation simple without
sacrificing advanced functionality.

Typical use cases won't require any additional options and even complex
PKI structure for TLS can be created with just few commands.

Note that it assumes that all generated keys and certificates can be used as
CAs (even if they have extensions that specifically forbid it). Because of
that, every single key pair is placed in a separate directory named as its
alias.

=cut

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Variables
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 VARIABLES

Below is the list of global variables. If they are already defined in
environment when the library is loaded, then will NOT be overwritten.

=over

=item x509PKEY

Name of file with private and public key. "key.pem" by default

=back

=cut

x509PKEY=${x509PKEY:-key.pem}

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

    x509KeyGen [-t type] [-s size] alias

=over

=item -t type

Type of key pair to generate. Acceptable values are "RSA" and "DSA". In
case the script is running on RHEL 6.5, RHEL 7.0, Fedora 19 or later, "ECDSA"
is also supported.

RSA by default.

=item -s size

Size of the used key for RSA and DSA. Name of the elliptic curve in case
of ECDSA key.

By default 2048 bit in case of RSA and DSA and prime256v1 in case of
ECDSA.

=item alias

Name of directory in which the generated key pair will be placed.
The file with key will be named "key.pem". If the directory does not exist
it will be created. Please don't put any unrelated files in it as they may
be overwritten by other functions.

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

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Execution
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

true <<'=cut'
=pod

=head1 EXECUTION

This library works correctly only when sourced.

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
