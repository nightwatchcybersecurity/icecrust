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
import json, sys, tempfile

import click, jsonschema
from download import download

from icecrust.canary_utils import CANARY_INPUT_SCHEMA, CANARY_OUTPUT_SCHEMA, IcecrustCanaryUtils, VerificationModes
from icecrust.cli import _process_result
from icecrust.utils import DEFAULT_HASH_ALGORITHM, IcecrustUtils


@click.version_option(version=IcecrustUtils.get_version(), prog_name='icecrust_canary')
@click.group()
def cli():
    """
    icecrust_canary - A canary tool for verification of software downloads.

    Copyright (c) 2021 Nightwatch Cybersecurity.
    Source code: https://github.com/nightwatchcybersecurity/icecrust
    """
    # TODO: Add input validation
    # TODO: Move private code into a separate module


@cli.command('verify')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('configfile', required=True, type=click.File('r'))
def verify(verbose, configfile):
    """Does a canary check against a project"""
    # Validate the file against the schema
    schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
    config = json.load(configfile)
    try:
        jsonschema.validators.validate(instance=config, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)
    except jsonschema.exceptions.ValidationError as err:
        click.echo("Config file is not properly formatted!")
        if verbose:
            click.echo(err.message)
        sys.exit(-1)

    # Create temporary directory and load file
    print('Downloading file: "' + config['filename_url'] + '"')
    temp_dir = str(tempfile.TemporaryDirectory().name)
    #file_req = download(config['filename_url'], temp_dir + '/file.dat', verbose=verbose, progressbar=verbose)

    # Select the right mode
    verification_mode =\
        IcecrustCanaryUtils.extract_verification_mode(config, IcecrustUtils.process_verbose_flag(verbose))
    if verification_mode is None:
        click.echo('Unknown verification mode in the config file!')
        sys.exit(-1)

    # Extract data and output details
    verification_data = config[str(verification_mode.value[0])]
    print('Using verification mode: ' + str(verification_mode.value[0]))
    if verbose:
        click.echo("Verification data: " + str(verification_data))

    # Initialize directory and PGP
    #temp_dir = str(tempfile.TemporaryDirectory().name)
    temp_dir = '/Users/yakovsh/Desktop/icecrust/test_data/gpg'
    gpg = IcecrustUtils.pgp_init(gpg_home_dir=temp_dir)

    # Do the right operation
    if verification_mode == VerificationModes.COMPARE_FILES:
        # Download the right files
        download(config['filename_url'], temp_dir + '/file1.dat', progressbar=verbose, verbose=verbose)
        download(verification_data['file2_url'], temp_dir + '/file2.dat', progressbar=verbose, verbose=verbose)

        # Compare files
        compare_result = IcecrustUtils.compare_files(temp_dir + '/file1.dat', temp_dir + '/file2.dat',
                                                     msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        _process_result(compare_result)
    elif verification_mode == VerificationModes.VERIFY_VIA_CHECKSUM:
        # Download the right files
        download(config['filename_url'], temp_dir + '/file1.dat', progressbar=verbose, verbose=verbose)

        # Check hash against checksum file
        algorithm = DEFAULT_HASH_ALGORITHM
        if 'algorithm' in verification_data:
            algorithm = verification_data['algorithm']
        checksum_valid = IcecrustUtils.verify_checksum(temp_dir + '/file1.dat', algorithm,
                                                       checksum_value=verification_data['checksum_value'],
                                                       msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        _process_result(checksum_valid)
    elif verification_mode == VerificationModes.VERIFY_VIA_CHECKSUMFILE:
        # Download the right files
        download(config['filename_url'], temp_dir + '/file1.dat', progressbar=verbose, verbose=verbose)
        download(verification_data['checksumfile_url'], temp_dir + '/checksums.dat',
                 progressbar=verbose, verbose=verbose)

        # Check hash against checksum file
        algorithm = DEFAULT_HASH_ALGORITHM
        if 'algorithm' in verification_data:
            algorithm = verification_data['algorithm']
        checksum_valid = IcecrustUtils.verify_checksum(temp_dir + '/file1.dat', algorithm,
                                                       checksumfile=temp_dir + '/checksums.dat',
                                                       msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        _process_result(checksum_valid)
    elif verification_mode == VerificationModes.VERIFY_VIA_PGP:
        # Import keys
        if 'keyfile_url' in verification_data:
            download(config['keyfile_url'], temp_dir + '/keys.txt', progressbar=verbose, verbose=verbose)
            IcecrustUtils.pgp_import_keys(gpg, keyfile=temp_dir + '/keys.txt',
                                          msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        else:
            IcecrustUtils.pgp_import_keys(gpg, keyid=verification_data['keyid'],
                                          keyserver=verification_data['keyserver'],
                                          msg_callback=IcecrustUtils.process_verbose_flag(verbose))

        # Download the right files
        download(config['filename_url'], temp_dir + '/file1.dat', progressbar=verbose, verbose=verbose)
        download(verification_data['signaturefile_url'], temp_dir + '/signature.dat',
                 progressbar=verbose, verbose=verbose)

        # Verify the signature first
        verification_result = IcecrustUtils.pgp_verify(gpg, temp_dir + '/file1.dat', temp_dir + '/signature.dat',
                                                       msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        _process_result(verification_result)
    elif verification_mode == VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE:
        # Import keys
        if 'keyfile_url' in verification_data:
            download(config['keyfile_url'], temp_dir + '/keys.txt', progressbar=verbose, verbose=verbose)
            IcecrustUtils.pgp_import_keys(gpg, keyfile=temp_dir + '/keys.txt',
                                          msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        else:
            IcecrustUtils.pgp_import_keys(gpg, keyid=verification_data['keyid'],
                                          keyserver=verification_data['keyserver'],
                                          msg_callback=IcecrustUtils.process_verbose_flag(verbose))

        # Download the right files
        download(config['filename_url'], temp_dir + '/file1.dat', progressbar=verbose, verbose=verbose)
        download(verification_data['checksumfile_url'], temp_dir + '/checksums.dat',
                 progressbar=verbose, verbose=verbose)
        download(verification_data['signaturefile_url'], temp_dir + '/signature.dat',
                 progressbar=verbose, verbose=verbose)

        # Verify the checksum file signature first
        verification_result = IcecrustUtils.pgp_verify(gpg, temp_dir + '/checksums.dat', temp_dir + '/signature.dat',
                                                       msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        if verification_result:
            # Check hash against checksum file
            algorithm = DEFAULT_HASH_ALGORITHM
            if 'algorithm' in verification_data:
                algorithm = verification_data['algorithm']
            checksum_valid = IcecrustUtils.verify_checksum(temp_dir + '/file1.dat', algorithm,
                                                           checksumfile=temp_dir + '/checksums.dat',
                                                           msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        _process_result(verification_result and checksum_valid)
    else:
        click.echo("ERROR: Verification mode not supported!")
        sys.exit(-1)


if __name__ == '__main__':
    cli(prog_name='icecrust_canary')