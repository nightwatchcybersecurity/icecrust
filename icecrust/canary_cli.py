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
from jsonschema.validators import validate

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
    schema_data = json.load(open(INPUT_SCHEMA, 'r'))
    parsed_data = json.load(open(TEST_DIR + 'canary/pnpm_input.json', 'r'))
    validate(instance=parsed_data, schema=schema_data)

    config = json.load(configfile)
    print('Checking "' + config['name'] + "', located at '" + config['url'] + "'")
    print('Verifying file: "' + config['filename_url'] + '"')
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
    cli(prog_name='icecrust_canary')