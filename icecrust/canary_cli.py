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
from datetime import datetime
from io import StringIO
from pathlib import Path
import json, sys, tempfile

import click, yaml, tzlocal

from icecrust.canary_utils import IcecrustCanaryUtils, VerificationModes
from icecrust.canary_utils import FILENAME_FILE1, FILENAME_FILE2, FILENAME_CHECKSUM, FILENAME_SIGNATURE
from icecrust.cli import _process_result
from icecrust.utils import IcecrustUtils


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
@click.option('--output-json-file', required=False, type=click.Path(dir_okay=False, exists=False))
@click.option('--output-upptime-file', required=False, type=click.Path(dir_okay=False, exists=False))
@click.argument('configfile', required=True, type=click.File('r'))
def verify(verbose, configfile, output_json_file, output_upptime_file):
    """Does a canary check against a project"""
    # Setup objects to be used
    cmd_output = []
    msg_callback = IcecrustUtils.process_verbose_flag(verbose)

    # Validate the config file
    config_data = IcecrustCanaryUtils.validate_config_file(configfile, msg_callback=msg_callback)
    if config_data is None:
        _process_result(False)

    # Select the right mode
    verification_mode =\
        IcecrustCanaryUtils.get_verification_mode(config_data, msg_callback=msg_callback)
    if verification_mode is None:
        click.echo('Unknown verification mode in the config file!')
        _process_result(False)
    print('Using verification mode: ' + verification_mode.name)

    # Extract verification data
    verification_data = IcecrustCanaryUtils.extract_verification_data(config_data, verification_mode,
                                                                      msg_callback=msg_callback)

    # Create temporary directory
    temp_dir_obj = tempfile.TemporaryDirectory()
    temp_dir = temp_dir_obj.name + '/'

    # Download all of the files required
    IcecrustCanaryUtils.download_all_files(verification_mode, temp_dir, config_data['filename_url'],
                                           verification_data, msg_callback=msg_callback)

    # Import keys for those operations that need it
    if verification_mode in [VerificationModes.VERIFY_VIA_PGP, VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE]:
        # Initialize PGP
        gpg = IcecrustUtils.pgp_init(gpg_home_dir=temp_dir_obj.name)

        # Import keys if needed
        import_result = IcecrustCanaryUtils.import_key_material(gpg, temp_dir, verification_data,
                                                                msg_callback=msg_callback)
        if import_result is False:
            _process_result(import_result)

    # Main operation code
    verification_result = False
    if verification_mode == VerificationModes.COMPARE_FILES:
        verification_result = IcecrustUtils.compare_files(temp_dir + FILENAME_FILE1, temp_dir + FILENAME_FILE2,
                                                          msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.VERIFY_VIA_CHECKSUM:
        algorithm = IcecrustCanaryUtils.get_algorithm(verification_data, msg_callback=msg_callback)
        verification_result = IcecrustUtils.verify_checksum(temp_dir + FILENAME_FILE1, algorithm,
                                                            checksum_value=verification_data['checksum_value'],
                                                            msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.VERIFY_VIA_CHECKSUMFILE:
        algorithm = IcecrustCanaryUtils.get_algorithm(verification_data, msg_callback=msg_callback)
        verification_result = IcecrustUtils.verify_checksum(temp_dir + FILENAME_FILE1, algorithm,
                                                            checksumfile=temp_dir + FILENAME_CHECKSUM,
                                                            msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.VERIFY_VIA_PGP:
        verification_result = IcecrustUtils.pgp_verify(gpg, temp_dir + FILENAME_FILE1, temp_dir + FILENAME_SIGNATURE,
                                                       msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE:
        # Verify the signature of the checksum file first
        signature_result = IcecrustUtils.pgp_verify(gpg, temp_dir + FILENAME_CHECKSUM, temp_dir + FILENAME_SIGNATURE,
                                                    msg_callback=msg_callback, cmd_output=cmd_output)

        # Then verify the checksums themselves
        if signature_result:
            algorithm = IcecrustCanaryUtils.get_algorithm(verification_data, msg_callback=msg_callback)
            verification_result = IcecrustUtils.verify_checksum(temp_dir + FILENAME_FILE1, algorithm,
                                                                checksumfile=temp_dir + FILENAME_CHECKSUM,
                                                                msg_callback=msg_callback, cmd_output=cmd_output)
    else:
        click.echo("ERROR: Verification mode not supported!")
        sys.exit(-1)

    # Generate JSON file if needed
    if output_json_file is not None:
        json_data = IcecrustCanaryUtils.generate_json(config_data, verification_mode, verification_result,
                                                        cmd_output, msg_callback)
        output_json_stream = open(output_json_file, "w")
        output_json_stream.write(json_data)
        output_json_stream.close()

    # Generate/update the UppTime if needed
    if output_upptime_file is not None:
        yaml_data = IcecrustCanaryUtils.generate_upptime(output_upptime_file, config_data, verification_result,
                                                         msg_callback)
        output_upptime_stream = open(output_upptime_file, "w")
        output_upptime_stream.write(yaml_data)
        output_upptime_stream.close()

    _process_result(verification_result)


if __name__ == '__main__':
    cli(prog_name='icecrust_canary')
