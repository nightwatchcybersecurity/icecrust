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
import json, pathlib, sys, tempfile

import click, gnupg
from download import download
from filehash import FileHash
from icecrust.utils import IcecrustUtils

@click.version_option(version=IcecrustUtils.get_version(), prog_name='icecrust')
@click.group()
def cli():
    """
    icecrust - A CI/CD-friendly tool for verification of software downloads using checksums and PGP.

    Copyright (c) 2021 Nightwatch Cybersecurity.
    Source code: https://github.com/nightwatchcybersecurity/icecrust
    """
    # TODO: Add input validation
    # TODO: Move private code into a separate module

@cli.command('checksumverify_with_keyid')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--algorithm', default='sha256', type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
@click.option('--keyid', required=True)
@click.option('--keyserver', required=True)
def checksumverify_with_keyid(filename, checksumfile, signaturefile, verbose, algorithm, keyid, keyserver):
    '''Verify checksum and PGP signature of a file based on a key id and server'''
    # Verify the checksum file signature first
    _pgpverify(checksumfile, signaturefile, verbose, keyid=keyid, keyserver=keyserver)

    # Check hash against checksum file
    checksum_valid = _checksum_verify(filename, checksumfile, algorithm)
    if checksum_valid:
        click.echo('File checksum verified against the checksums file')
    else:
        click.echo('ERROR: File checksum cannot be found or verified!')
        sys.exit(-1)

@cli.command('checksumverify_with_keyfile')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--keyfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default='sha256', type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def checksumverify_with_keyfile(filename, checksumfile, signaturefile, verbose, algorithm, keyfile):
    '''Verify checksum and PGP signature of a file based on a key id and server'''
    # Verify the checksum file signature first
    _pgpverify(checksumfile, signaturefile, verbose, keyfile=keyfile)

    # Check hash against checksum file
    checksum_valid = _checksum_verify(filename, checksumfile, algorithm)
    if checksum_valid:
        click.echo('File checksum verified against the checksums file')
    else:
        click.echo('ERROR: File checksum cannot be found or verified!')
        sys.exit(-1)


def _checksum_verify(filename, checksumfile, algorithm):
    # Calculate the checksum
    hasher = FileHash(algorithm)
    hash = hasher.hash_file(filename=filename)

    # Check hash against checksum file
    checksums = pathlib.Path(checksumfile).read_text()
    if hash in checksums:
        return True
    else:
        return False

@cli.command('pgpverify_with_keyfile')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--keyfile', required=True, type=click.Path(exists=True, dir_okay=False))
def pgpverify_with_keyfile(filename, signaturefile, verbose, keyfile):
    '''Verify PGP signature of a file based on a keyfile'''
    _pgpverify(filename, signaturefile, verbose, keyfile=keyfile)

@cli.command('pgpverify_with_keyid')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyid', required=True)
@click.option('--keyserver', required=True)
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
def pgpverify_with_keyid(filename, signaturefile, keyid, keyserver, verbose):
    '''Verify PGP signature of a file based on a key id and server'''
    _pgpverify(filename, signaturefile, keyid=keyid, keyserver=keyserver)

def _pgpverify(filename, signaturefile, verbose, temp_dir=None, keyfile=None, keyid=None, keyserver=None):
    # Setup GPG
    if temp_dir is None:
        gpg_home = tempfile.TemporaryDirectory()
        gpg = gnupg.GPG(gnupghome=gpg_home.name)
    else:
        gpg = gnupg.GPG(gnupghome=temp_dir)

    # Import keys from file or server
    if keyfile:
        keydata = pathlib.Path(keyfile).read_text()
        import_result = gpg.import_keys(keydata)
    else:
        import_result = gpg.recv_keys(keyserver, keyid)
    if verbose:
        click.echo('--- Results of key import ---\n')
        click.echo(import_result.stderr)

    if import_result.imported == 0:
        click.echo('ERROR: No keys found')
        sys.exit(-1)

    # Verify signature
    signature = open(signaturefile, "rb")
    verification_result = gpg.verify_file(signature, filename)
    if verbose:
         click.echo('\n--- Results of verification ---')
         click.echo(verification_result.stderr)

    if verification_result.status != 'signature valid':
        click.echo('ERROR: Unable to verify file')
        sys.exit(-1)

    click.echo(verification_result.status)


@cli.command('canary')
@click.argument('configfile', required=True, type=click.File('r'))
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
def canary(configfile, verbose):
    '''Does a canary check against a project'''
    # TODO: Add JSON schema scheck
    config = json.load(configfile)
    print('Checking "' + config['name'] + "', located at '" + config['url'] + "'")
    print('Verifying file: "' + config['filename_url'] + '"')

    # Select the right mode
    if config['verification_mode'] == 'checksumverify_with_keyid':
        #temp_dir = str(tempfile.TemporaryDirectory().name)
        temp_dir = '/Users/yakovsh/Desktop/icecrust/test_data/canary'

        # Download the right files
        file_req = download(config['filename_url'], temp_dir + '/file.dat')
        checksum_req = download(config['checksumfile_url'], temp_dir + '/checksums.dat')
        signature_req = download(config['signaturefile_url'], temp_dir + '/signature.dat')

        # Verify the checksum file signature first
        _pgpverify(temp_dir + '/checksums.dat', temp_dir + '/signature.dat', verbose,
                   keyid=config['keyid'], keyserver=config['keyserver'])

        # Check hash against checksum file
        checksum_valid = _checksum_verify(temp_dir + '/file.dat', temp_dir + '/checksums.dat',
                                          config['algorithm'])
        if checksum_valid:
            click.echo('File checksum verified against the checksums file')
        else:
            click.echo('ERROR: File checksum cannot be found or verified!')
            sys.exit(-1)
    elif config['verification_mode'] == 'checksumverify_with_keyfile':
        pass
    elif config['verification_mode'] == 'pgpverify_with_keyfile':
        pass
    elif config['verification_mode'] == 'pgpverify_with_keyid':
        pass
    else:
        click.echo('ERROR: Unknown verification mode')
        sys.exit(-1)


if __name__ == '__main__':
    cli(prog_name='icecrust')