#
# Copyright (c) 2021 Nightwatch Cybersecurity.
#
# This file is part of icetrust
# (see https://github.com/nightwatchcybersecurity/icetrust).
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
import os, shutil, sys, tempfile

import click
from icetrust.utils import DEFAULT_HASH_ALGORITHM, IcetrustUtils
from icetrust.utils_canary import FILENAME_FILE1, FILENAME_FILE2, FILENAME_CHECKSUM, FILENAME_SIGNATURE,\
    IcetrustCanaryUtils, VerificationModes


@click.version_option(version=IcetrustUtils.get_version(), prog_name='icetrust')
@click.group()
def cli():
    """
    icetrust - A tool for verification of software downloads using checksums and/or PGP.

    Copyright (c) 2021 Nightwatch Cybersecurity.
    Source code: https://github.com/nightwatchcybersecurity/icetrust
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
@click.option('--output-json', required=False, type=click.Path(dir_okay=False, exists=False),
              help='Output results of the command into a JSON file')
@click.option('--save-file', required=False, type=click.Path(dir_okay=False, exists=False),
              help='Saves the downloaded file to the provided location')
@click.argument('configfile', required=True, type=click.File('r'))
def canary(verbose, configfile, output_json, save_file):
    """Does a canary check against a project using information in CONFIGFILE"""
    # Setup objects to be used
    cmd_output = []
    msg_callback = IcetrustUtils.process_verbose_flag(verbose)

    # Validate the config file
    config_data = IcetrustCanaryUtils.validate_config_file(configfile, msg_callback=msg_callback)
    if config_data is None:
        _process_result(False)

    # Select the right mode
    verification_mode =\
        IcetrustCanaryUtils.get_verification_mode(config_data, msg_callback=msg_callback)
    if verification_mode is None:
        click.echo('Unknown verification mode in the config file!')
        _process_result(False)
    print('Using verification mode: ' + verification_mode.name)

    # Extract verification data
    verification_data = IcetrustCanaryUtils.extract_verification_data(config_data, verification_mode,
                                                                      msg_callback=msg_callback)

    # Check verification_data for warnings
    if verbose:
        IcetrustCanaryUtils.check_verification_data(config_data, verification_mode, verification_data,
                                                    msg_callback=msg_callback)

    # Create temporary directory
    temp_dir_obj = tempfile.TemporaryDirectory()
    temp_dir = os.path.join(temp_dir_obj.name, '')

    # Download all of the files required
    IcetrustCanaryUtils.download_all_files(verification_mode, temp_dir, config_data['filename_url'],
                                           verification_data, msg_callback=msg_callback)

    # Import keys for those operations that need it
    if verification_mode in [VerificationModes.PGP, VerificationModes.PGPCHECKSUMFILE]:
        # Initialize PGP
        gpg = IcetrustUtils.pgp_init(gpg_home_dir=temp_dir_obj.name)

        # Import keys if needed
        import_output = []
        import_result = IcetrustCanaryUtils.import_key_material(gpg, temp_dir, verification_data,
                                                                cmd_output=import_output,
                                                                msg_callback=msg_callback)
        if import_result is False:
            if output_json is not None:
                json_data = IcetrustCanaryUtils.generate_json(config_data, verification_mode, import_result,
                                                              import_output, os.path.join(temp_dir, FILENAME_FILE1),
                                                              msg_callback)
                open(output_json, "w").write(json_data)

            _process_result(import_result)

    # Main operation code
    verification_result = False
    if verification_mode == VerificationModes.COMPARE_FILES:
        verification_result = IcetrustUtils.compare_files(os.path.join(temp_dir, FILENAME_FILE1),
                                                          os.path.join(temp_dir, FILENAME_FILE2),
                                                          msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.CHECKSUM:
        algorithm = IcetrustCanaryUtils.get_algorithm(verification_data, msg_callback=msg_callback)
        verification_result = IcetrustUtils.verify_checksum(os.path.join(temp_dir, FILENAME_FILE1), algorithm,
                                                            checksum_value=verification_data['checksum_value'],
                                                            msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.CHECKSUMFILE:
        algorithm = IcetrustCanaryUtils.get_algorithm(verification_data, msg_callback=msg_callback)
        verification_result = IcetrustUtils.verify_checksum(os.path.join(temp_dir, FILENAME_FILE1), algorithm,
                                                            checksumfile=os.path.join(temp_dir, FILENAME_CHECKSUM),
                                                            msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.PGP:
        verification_result = IcetrustUtils.pgp_verify(gpg, os.path.join(temp_dir, FILENAME_FILE1),
                                                       os.path.join(temp_dir, FILENAME_SIGNATURE),
                                                       msg_callback=msg_callback, cmd_output=cmd_output)
    elif verification_mode == VerificationModes.PGPCHECKSUMFILE:
        # Verify the signature of the checksum file first
        signature_result = IcetrustUtils.pgp_verify(gpg, os.path.join(temp_dir, FILENAME_CHECKSUM),
                                                    os.path.join(temp_dir, FILENAME_SIGNATURE),
                                                    msg_callback=msg_callback, cmd_output=cmd_output)

        # Then verify the checksums themselves
        if signature_result:
            algorithm = IcetrustCanaryUtils.get_algorithm(verification_data, msg_callback=msg_callback)
            verification_result = IcetrustUtils.verify_checksum(os.path.join(temp_dir, FILENAME_FILE1), algorithm,
                                                                checksumfile=os.path.join(temp_dir, FILENAME_CHECKSUM),
                                                                msg_callback=msg_callback, cmd_output=cmd_output)
    else:
        click.echo("ERROR: Verification mode not supported!")
        sys.exit(-1)

    # Compare previous version if needed
    comparison_result = None
    if 'previous_version' in config_data:
        previous_file_path = os.path.join(os.getcwd(), config_data['previous_version'])
        if os.path.exists(previous_file_path):
            click.echo('\nComparing with previous version...')
            comparison_result = IcetrustUtils.compare_files(config_data['previous_version'],
                                                            os.path.join(temp_dir, FILENAME_FILE1),
                                                            msg_callback=msg_callback)
            if comparison_result:
                click.echo('File matches previous version')
            else:
                click.echo('ERROR: File doesn\'t match previous version!')

    # Saves the file if needed
    if save_file is not None:
        click.echo('\nSaving file...')
        shutil.copy(os.path.join(temp_dir, FILENAME_FILE1), save_file)

    # Generate JSON file if needed
    if output_json is not None:
        json_data = IcetrustCanaryUtils.generate_json(config_data, verification_mode,
                                                      verification_result, comparison_result,
                                                      cmd_output, os.path.join(temp_dir, FILENAME_FILE1),
                                                      msg_callback)
        open(output_json, "w").write(json_data)

    _process_result(verification_result)


@cli.command('compare_files')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('file1', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('file2', required=True, type=click.Path(exists=True, dir_okay=False))
def compare_files(verbose, file1, file2):
    """Compares FILE1 against FILE2 by calculating checksums"""
    comparison_result = IcetrustUtils.compare_files(file1, file2,
                                                    msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    _process_result(comparison_result)


@cli.command('checksum')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksum_value', required=True)
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, help='Hash algorithm to be used (sha1, sha256 or sha512)',
              type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def checksum(verbose, filename, checksum_value, algorithm):
    """Verify FILENAME against the CHECKSUM_VALUE"""
    checksum_valid = IcetrustUtils.verify_checksum(filename, algorithm, checksum_value=checksum_value,
                                                   msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    _process_result(checksum_valid)


@cli.command('checksumfile')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, help='Hash algorithm to be used (sha1, sha256 or sha512)',
              type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
def checksumfile(verbose, filename, checksumfile, algorithm):
    """Verify FILENAME against a checksum value in the CHECKSUMFILE"""
    checksum_valid = IcetrustUtils.verify_checksum(filename, algorithm, checksumfile=checksumfile,
                                                   msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    _process_result(checksum_valid)


@cli.command('pgp')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--keyfile', required=False, type=click.Path(exists=True, dir_okay=False),
              help='File containing PGP keys')
@click.option('--keyid', required=False, help='PGP key ID')
@click.option('--keyserver', required=False, help='Domain name of the PGP keyserver')
def pgp(verbose, filename, signaturefile, keyfile, keyid, keyserver):
    """Verify FILENAME via a PGP signature in SIGNATUREFILE using provided keys"""
    # Check input parameters
    if keyfile is None and (keyid is None or keyserver is None):
        click.echo("ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!")
        sys.exit(2)

    # Initialize PGP and import keys
    gpg = IcetrustUtils.pgp_init(verbose)
    import_result = IcetrustUtils.pgp_import_keys(gpg, keyfile=keyfile, keyid=keyid, keyserver=keyserver,
                                                  msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    if import_result is False:
        _process_result(import_result)

    # Verify file
    verification_result = IcetrustUtils.pgp_verify(gpg, filename, signaturefile,
                                                   msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    _process_result(verification_result)


@cli.command('pgpchecksumfile')
@click.option('--verbose', is_flag=True, help='Output additional information during the verification process')
@click.argument('filename', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('checksumfile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('signaturefile', required=True, type=click.Path(exists=True, dir_okay=False))
@click.option('--algorithm', default=DEFAULT_HASH_ALGORITHM, help='Hash algorithm to be used (sha1, sha256 or sha512)',
              type=click.Choice(['sha1', 'sha256', 'sha512'], case_sensitive=False))
@click.option('--keyfile', required=False, type=click.Path(exists=True, dir_okay=False),
              help='File containing PGP keys')
@click.option('--keyid', required=False, help='PGP key ID')
@click.option('--keyserver', required=False, help='Domain name of the PGP keyserver')
def pgpchecksumfile(verbose, filename, checksumfile, signaturefile, algorithm, keyfile, keyid, keyserver):
    """Verify FILENAME via a PGP-signed CHECKSUMFILE, with a signature in SIGNATUREFILE using provided keys"""
    # Check input parameters
    if keyfile is None and (keyid is None or keyserver is None):
        click.echo("ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!")
        sys.exit(2)

    # Initialize PGP and import keys
    gpg = IcetrustUtils.pgp_init(verbose)
    import_result = IcetrustUtils.pgp_import_keys(gpg, keyfile=keyfile, keyid=keyid, keyserver=keyserver,
                                                  msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    if import_result is False:
        _process_result(import_result)

    # Verify checksums file
    verification_result = IcetrustUtils.pgp_verify(gpg, checksumfile, signaturefile,
                                                   msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    if verification_result.status is False:
        _process_result(verification_result)

    # Check hash against the checksums file
    checksum_valid = IcetrustUtils.verify_checksum(filename, algorithm, checksumfile=checksumfile,
                                                   msg_callback=IcetrustUtils.process_verbose_flag(verbose))
    _process_result(checksum_valid)


if __name__ == '__main__':
    cli(prog_name='icetrust')
