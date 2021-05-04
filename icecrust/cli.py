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
import sys, tempfile

import click
from icecrust.utils import DEFAULT_HASH_ALGORITHM, IcecrustUtils
from icecrust.utils_canary import FILENAME_FILE1, FILENAME_FILE2, FILENAME_CHECKSUM, FILENAME_SIGNATURE,\
    IcecrustCanaryUtils, VerificationModes


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


def _process_result(verification_result):
    """Process verification results and exit"""
    if verification_result:
        click.echo('File verified')
        sys.exit(0)
    else:
        click.echo('ERROR: File cannot be verified!')
        sys.exit(-1)


@cli.command('canary')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.option('--output-json-file', required=False, type=click.Path(dir_okay=False, exists=False))
@click.argument('configfile', required=True, type=click.File('r'))
def canary(verbose, configfile, output_json_file, output_upptime_file):
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

    _process_result(verification_result)


@cli.command('compare_files')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('file1', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('file2', required=True, type=click.Path(exists=True, dir_okay=False))
def compare_files(verbose, file1, file2):
    """Compares two files by calculating hashes"""
    comparison_result = IcecrustUtils.compare_files(file1, file2,
                                                    msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    _process_result(comparison_result)


@cli.command('verify_via_checksum')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--checksum_value', required=True)
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'],
                                                                               case_sensitive=False))
def verify_via_checksum(verbose, filename, checksum_value, algorithm):
    """Verify via a checksum value"""
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksum_value=checksum_value,
                                                   msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    _process_result(checksum_valid)


@cli.command('verify_via_checksumfile')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'],
                                                                               case_sensitive=False))
def verify_via_checksumfile(verbose, filename, checksumfile, algorithm):
    """Verify via a checksums file"""
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksumfile=checksumfile,
                                                   msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    _process_result(checksum_valid)


@cli.command('verify_via_pgp')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyfile', required=False, type=click.Path(exists=True, dir_okay=False), help='File containing PGP keys')
@click.option('--keyid', required=False, help='PGP key ID')
@click.option('--keyserver', required=False, help='Domain name of the PGP keyserver')
def verify_via_pgp(verbose, filename, signaturefile, keyfile, keyid, keyserver):
    """Verify via a PGP signature"""
    # Check input parameters
    if keyfile is None and (keyid is None or keyserver is None):
        click.echo("ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!")
        sys.exit(2)

    # Initialize PGP and import keys
    gpg = IcecrustUtils.pgp_init(verbose)
    import_result = IcecrustUtils.pgp_import_keys(gpg, keyfile=keyfile, keyid=keyid, keyserver=keyserver,
                                                  msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    if import_result is False:
        _process_result(import_result)

    # Verify file
    verification_result = IcecrustUtils.pgp_verify(gpg, filename, signaturefile,
                                                   msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    _process_result(verification_result)


@cli.command('verify_via_pgpchecksumfile')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, type=click.Choice(['sha1', 'sha256', 'sha512'],
                                                                               case_sensitive=False))
@click.option('--keyfile', required=False, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyid', required=False)
@click.option('--keyserver', required=False)
def verify_via_pgpchecksumfile(verbose, filename, checksumfile, signaturefile, algorithm, keyfile, keyid, keyserver):
    """Verify via a PGP-signed checksums file"""
    # Check input parameters
    if keyfile is None and (keyid is None or keyserver is None):
        click.echo("ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!")
        sys.exit(2)

    # Initialize PGP and import keys
    gpg = IcecrustUtils.pgp_init(verbose)
    import_result = IcecrustUtils.pgp_import_keys(gpg, keyfile=keyfile, keyid=keyid, keyserver=keyserver,
                                                  msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    if import_result is False:
        _process_result(import_result)

    # Verify checksums file
    verification_result = IcecrustUtils.pgp_verify(gpg, checksumfile, signaturefile,
                                                   msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    if verification_result.status is False:
        _process_result(verification_result)

    # Check hash against the checksums file
    checksum_valid = IcecrustUtils.verify_checksum(filename, algorithm, checksumfile=checksumfile,
                                                   msg_callback=IcecrustUtils.process_verbose_flag(verbose))
    _process_result(checksum_valid)


if __name__ == '__main__':
    cli(prog_name='icecrust')
