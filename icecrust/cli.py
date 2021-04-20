#
# Copyright (c) 2021 Nightwatch Cybersecurity.
#
# This file is part of icecrust
# (see https://github.com/nightwatchcybersecurity/icecrust).
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
import json, sys

import click
from download import download
from icecrust.utils import DEFAULT_HASH_ALGORITHM, IcecrustUtils

@click.version_option(version=IcecrustUtils.get_version(), prog_name='icecrust')
@click.group()
def cli():
    """
    icecrust - A tool for verification of software downloads using checksums and PGP.

    Copyright (c) 2021 Nightwatch Cybersecurity.
    Source code: https://github.com/nightwatchcybersecurity/icecrust
    """
    # TODO: Add input validation
    # TODO: Move private code into a separate module

@cli.command('comparefiles')
@click.argument('file1', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('file2', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
def comparefiles(file1, file2, verbose):
    """Compares two files (using SHA-256 hashes)"""
    # Calculate the checksums and return result
    comparison_result = IcecrustUtils.compare_files(file1, file2, verbose)
    if comparison_result:
        click.echo('File verified')
    else:
        click.echo('ERROR: File verified!')
        sys.exit(-1)


@cli.command('verifychecksum')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--checksum', required=True)
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def verify_checksum_with_file(filename, checksum, verbose, algorithm):
    '''Verify with hash and checksum value'''
    # Check hash and output results
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksum=checksum)
    if checksum_valid:
        click.echo('File verified')
    else:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)


@cli.command('verifychecksum_with_file')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def verify_checksum_with_file(filename, checksumfile, verbose, algorithm):
    '''Verify with hash and checksums file'''
    # Check hash and output results
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksumfile=checksumfile)
    if checksum_valid:
        click.echo('File verified')
    else:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)


@cli.command('verifychecksum_with_keyid')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
@click.option('--keyid', required=True)
@click.option('--keyserver', required=True)
def verifychecksum_with_keyid(filename, checksumfile, signaturefile, verbose, algorithm, keyid, keyserver):
    '''Verify with hash and PGP using a key id'''
    # Verify the checksum file signature first
    IcecrustUtils.pgpverify(checksumfile, signaturefile, verbose, keyid=keyid, keyserver=keyserver)

    # Check hash against checksum file
    checksum_valid = IcecrustUtils.verify_checksum(filename, checksumfile, algorithm)
    if checksum_valid:
        click.echo('File checksum verified against the checksums file')
    else:
        click.echo('ERROR: File checksum cannot be found or verified!')
        sys.exit(-1)


@cli.command('verifychecksum_with_keyfile')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--keyfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def verifychecksum_with_keyfile(filename, checksumfile, signaturefile, verbose, algorithm, keyfile):
    '''Verify with hash and PGP using a key file'''
    # Verify the checksum file signature first
    IcecrustUtils.pgpverify(checksumfile, signaturefile, verbose, keyfile=keyfile)

    # Check hash against checksum file
    checksum_valid = IcecrustUtils.verify_checksum(filename, checksumfile, algorithm)
    if checksum_valid:
        click.echo('File checksum verified against the checksums file')
    else:
        click.echo('ERROR: File checksum cannot be found or verified!')
        sys.exit(-1)


@cli.command('verifypgp_with_keyfile')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--keyfile', required=True, type=click.Path(exists=True, dir_okay=False))
def verifypgp_with_keyfile(filename, signaturefile, verbose, keyfile):
    '''Verify with PGP using a keyfile'''
    IcecrustUtils.pgpverify(filename, signaturefile, verbose, keyfile=keyfile)


@cli.command('verifypgp_with_keyid')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyid', required=True)
@click.option('--keyserver', required=True)
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
def verifypgp_with_keyid(filename, signaturefile, keyid, keyserver, verbose):
    '''Verify with PGP using a key id'''
    IcecrustUtils.pgpverify(filename, signaturefile, keyid=keyid, keyserver=keyserver)


# @cli.command('canary')
# @click.argument('configfile', required=True, type=click.File('r'))
# @click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
# def canary(configfile, verbose):
#     '''Does a canary check against a project'''
#     # TODO: Add JSON schema scheck
#     config = json.load(configfile)
#     print('Checking "' + config['name'] + "', located at '" + config['url'] + "'")
#     print('Verifying file: "' + config['filename_url'] + '"')
#
#     # Select the right mode
#     if config['verification_mode'] == 'checksumverify_with_keyid':
#         #temp_dir = str(tempfile.TemporaryDirectory().name)
#         temp_dir = '/Users/yakovsh/Desktop/icecrust/test_data/canary'
#
#         # Download the right files
#         file_req = download(config['filename_url'], temp_dir + '/file.dat')
#         checksum_req = download(config['checksumfile_url'], temp_dir + '/checksums.dat')
#         signature_req = download(config['signaturefile_url'], temp_dir + '/signature.dat')
#
#         # Verify the checksum file signature first
#         IcecrustUtils.pgpverify(temp_dir + '/checksums.dat', temp_dir + '/signature.dat', verbose,
#                    keyid=config['keyid'], keyserver=config['keyserver'])
#
#         # Check hash against checksum file
#         checksum_valid = IcecrustUtils.verify_file_checksum(temp_dir + '/file.dat', temp_dir + '/checksums.dat',
#                                           config['algorithm'])
#         if checksum_valid:
#             click.echo('File checksum verified against the checksums file')
#         else:
#             click.echo('ERROR: File checksum cannot be found or verified!')
#             sys.exit(-1)
#     elif config['verification_mode'] == 'checksumverify_with_keyfile':
#         pass
#     elif config['verification_mode'] == 'pgpverify_with_keyfile':
#         pass
#     elif config['verification_mode'] == 'pgpverify_with_keyid':
#         pass
#     else:
#         click.echo('ERROR: Unknown verification mode')
#         sys.exit(-1)


if __name__ == '__main__':
    cli(prog_name='icecrust')