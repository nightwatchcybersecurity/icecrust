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


def _process_verbose_flag(verbose):
    """
    Return message callback object to be used for output, usually click

    :param verbose: if True, return an object to be used for output
    :return: message callback object
    """
    if verbose:
        return click
    else:
        return False


@click.version_option(version=IcecrustUtils.get_version(), prog_name='icecrust')
@click.group()
def cli():
    """
    icecrust - A tool for verification of software downloads using checksums and/or PGP.

    Copyright (c) 2021 Nightwatch Cybersecurity.
    Source code: https://github.com/nightwatchcybersecurity/icecrust
    """
    # TODO: Add input validation
    # TODO: Move private code into a separate module


@cli.command('compare_files')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('file1', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('file2', required=True, type=click.Path(exists=True, dir_okay=False))
def compare_files(verbose, file1, file2):
    """Compares two files by calculating hashes"""
    # Calculate the checksums and return result
    comparison_result = IcecrustUtils.compare_files(file1, file2,
                                                    msg_callback=_process_verbose_flag(verbose))
    if comparison_result:
        click.echo('Files verified')
    else:
        click.echo('ERROR: Files cannot be verified!')
        sys.exit(-1)


@cli.command('verify_via_checksum')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--checksum', required=True)
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def verify_via_checksum(verbose, filename, checksum, algorithm):
    """Verify via a checksum value"""
    # Check hash and output results
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksum=checksum,
                                                   msg_callback=_process_verbose_flag(verbose))
    if checksum_valid:
        click.echo('File verified')
    else:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)


@cli.command('verify_via_checksumfile')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def verify_via_checksumfile(verbose, filename, checksumfile, algorithm):
    """Verify via a checksums file"""
    # Check hash and output results
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksumfile=checksumfile,
                                                   msg_callback=_process_verbose_flag(verbose))
    if checksum_valid:
        click.echo('File verified')
    else:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)

@cli.command('verify_via_pgp')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyfile', required=False, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyid', required=False)
@click.option('--keyserver', required=False)
def verify_via_pgp(verbose, filename, signaturefile, keyfile, keyid, keyserver):
    """Verify via a PGP signature"""
    # Check input parameters
    if keyfile is None and keyid is None and keyserver is None:
        click.echo("ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!")
        exit(-1)
    elif keyfile is None and (keyid is None or keyserver is None):
        click.echo("ERROR: Both '--keyid' and '--keyserver' parameters must be set!")
        exit(-1)

    # Initialize PGP and import keys
    gpg = IcecrustUtils.pgp_init(verbose)
    import_result = IcecrustUtils.pgp_import_keys(gpg, keyfile=keyfile, keyid=keyid, keyserver=keyserver,
                                                  msg_callback=_process_verbose_flag(verbose))
    if import_result is False:
        click.echo('ERROR: No keys found')
        sys.exit(-1)

    # Verify file
    verification_result = IcecrustUtils.pgpverify(gpg, filename, signaturefile,
                                                  msg_callback=_process_verbose_flag(verbose))
    if verification_result.status is True:
        click.echo('File verified')
    else:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)


@cli.command('verify_via_pgpchecksumfile')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
@click.option('--keyfile', required=False, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyid', required=False)
@click.option('--keyserver', required=False)
def verify_via_pgpchecksumfile(verbose, filename, checksumfile, signaturefile, algorithm, keyfile, keyid, keyserver):
    """Verify via a PGP-signed checksums file"""
    # Check input parameters
    if keyfile is None and keyid is None and keyserver is None:
        click.echo("ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!")
        exit(-1)
    elif keyfile is None and (keyid is None or keyserver is None):
        click.echo("ERROR: Both '--keyid' and '--keyserver' parameters must be set!")
        exit(-1)

    # Initialize PGP and import keys
    gpg = IcecrustUtils.pgp_init(verbose)
    import_result = IcecrustUtils.pgp_import_keys(gpg, keyfile=keyfile, keyid=keyid, keyserver=keyserver,
                                                  msg_callback=_process_verbose_flag(verbose))
    if import_result is False:
        click.echo('ERROR: No keys found')
        sys.exit(-1)

    # Verify checksums file
    verification_result = IcecrustUtils.pgpverify(gpg, checksumfile, signaturefile,
                                                  msg_callback=_process_verbose_flag(verbose))
    if verification_result.status is False:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)

    # Check hash against the checksums file
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksumfile=checksumfile,
                                                   msg_callback=_process_verbose_flag(verbose))
    if checksum_valid:
        click.echo('File verified')
    else:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)


# @cli.command('canary')
# @click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
# @click.argument('configfile', required=True, type=click.File('r'))
# def canary(verbose, configfile):
#     """Does a canary check against a project"""
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