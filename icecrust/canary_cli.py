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

from icecrust.canary_utils import IcecrustCanaryUtils, VerificationModes
from icecrust.canary_utils import FILENAME_FILE1, FILENAME_FILE2, FILENAME_KEYS, FILENAME_CHECKSUM, FILENAME_SIGNATURE
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
    # Validate the config file
    config_data = IcecrustCanaryUtils.validate_config_file(configfile, IcecrustUtils.process_verbose_flag(verbose))
    if config_data is None:
        _process_result(False)

    # Create temporary directory and download file to be checked
    print('Downloading file: "' + config_data['filename_url'] + '"')
    temp_dir = str(tempfile.TemporaryDirectory().name)
    #file_req = download(config['filename_url'], temp_dir + '/file.dat', verbose=verbose, progressbar=verbose)

    # Select the right mode
    verification_mode =\
        IcecrustCanaryUtils.extract_verification_mode(config_data, IcecrustUtils.process_verbose_flag(verbose))
    if verification_mode is None:
        click.echo('Unknown verification mode in the config file!')
        _process_result(False)

    # Extract data and output details
    verification_data = config_data[str(verification_mode.value[0])]
    print('Using verification mode: ' + str(verification_mode.value[0]))
    if verbose:
        click.echo("Verification data: " + str(verification_data))

    # Initialize directory and PGP
    #temp_dir = str(tempfile.TemporaryDirectory().name)
    temp_dir = '/Users/yakovsh/Desktop/icecrust/test_data/gpg'
    gpg = IcecrustUtils.pgp_init(gpg_home_dir=temp_dir)

    # Download all of the files required
    IcecrustCanaryUtils.download_all_files(verification_mode, temp_dir, config_data['filename_url'],
                                           verification_data, msg_callback=IcecrustUtils.process_verbose_flag(verbose))

    # Import keys for those operations that need it
    if verification_mode in [VerificationModes.VERIFY_VIA_PGP, VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE]:
        import_result = IcecrustCanaryUtils.import_keys(gpg, temp_dir, verification_data,
                                                        msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        if import_result is False:
            _process_result(import_result)

    # Main operation code
    verification_result = False
    if verification_mode == VerificationModes.COMPARE_FILES:
        verification_result = IcecrustUtils.compare_files(temp_dir + FILENAME_FILE1, temp_dir + FILENAME_FILE2,
                                                     msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    elif verification_mode == VerificationModes.VERIFY_VIA_CHECKSUM:
        algorithm = IcecrustCanaryUtils.get_algorithm(verification_data,
                                                      msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        verification_result = IcecrustUtils.verify_checksum(temp_dir + FILENAME_FILE1, algorithm,
                                                       checksum_value=verification_data['checksum_value'],
                                                       msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    elif verification_mode == VerificationModes.VERIFY_VIA_CHECKSUMFILE:
        algorithm = IcecrustCanaryUtils.get_algorithm(verification_data,
                                                      msg_callback=IcecrustUtils.process_verbose_flag(verbose))
        verification_result = IcecrustUtils.verify_checksum(temp_dir + FILENAME_FILE1, algorithm,
                                                       checksumfile=temp_dir + FILENAME_CHECKSUM,
                                                       msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    elif verification_mode == VerificationModes.VERIFY_VIA_PGP:
        verification_result = IcecrustUtils.pgp_verify(gpg, temp_dir + FILENAME_FILE1, temp_dir + FILENAME_SIGNATURE,
                                                       msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    elif verification_mode == VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE:
        # Verify the signature of the checksum file first
        signature_result = IcecrustUtils.pgp_verify(gpg, temp_dir + FILENAME_CHECKSUM, temp_dir + FILENAME_SIGNATURE,
                                                    msg_callback=IcecrustUtils.process_verbose_flag(verbose))

        # Then verify the checksums themselves
        if signature_result:
            algorithm = IcecrustCanaryUtils.get_algorithm(verification_data,
                                                          msg_callback=IcecrustUtils.process_verbose_flag(verbose))
            verification_result = IcecrustUtils.verify_checksum(temp_dir + FILENAME_FILE1, algorithm,
                                                                checksumfile=temp_dir + FILENAME_CHECKSUM,
                                                                msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    else:
        click.echo("ERROR: Verification mode not supported!")
        sys.exit(-1)

    # Finish
    _process_result(verification_result)


if __name__ == '__main__':
    cli(prog_name='icecrust_canary')
