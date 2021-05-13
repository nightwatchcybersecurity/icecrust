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
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse
import json, os, pkg_resources, shutil

from download import download
from filehash import filehash
import click, jsonschema, tzlocal

from icetrust.utils import DEFAULT_HASH_ALGORITHM, IcetrustUtils


# Location of the schema files
CANARY_INPUT_SCHEMA  = pkg_resources.resource_filename('icetrust', os.path.join('data', 'canary_input.schema.json'))
CANARY_OUTPUT_SCHEMA = pkg_resources.resource_filename('icetrust', os.path.join('data', 'canary_output.schema.json'))

# Names of files to be downloaded
FILENAME_FILE1 = "file1.dat"
FILENAME_FILE2 = "file2.dat"
FILENAME_KEYS = "pgp_keys.txt"
FILENAME_CHECKSUM = "checksum.dat"
FILENAME_SIGNATURE = "signature.dat"


# List of available verification modes, based on the command line options in the main CLI class
class VerificationModes(Enum):
    COMPARE_FILES = 'compare_files',
    CHECKSUM = 'checksum',
    CHECKSUMFILE = 'checksumfile',
    PGP = 'pgp',
    PGPCHECKSUMFILE = 'pgpchecksumfile'


class IcetrustCanaryUtils(object):
    """Various utility functions for the canary CLI"""
    @staticmethod
    def check_verification_data(config_data, verification_mode, verification_data, msg_callback=None):
        """
        Checks verification data for possible warnings

        :param config_data: data extracted from the config file
        :param verification_mode: verification mode being used
        :param verification_data: parsed JSON containing verification data
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        """
        filename_url = urlparse(config_data['filename_url'])
        file2_url = None
        if verification_mode == VerificationModes.COMPARE_FILES:
            file2_url = urlparse(verification_data['file2_url'])
        elif verification_mode == VerificationModes.CHECKSUM:
            pass
        elif verification_mode == VerificationModes.CHECKSUMFILE:
            file2_url = urlparse(verification_data['checksumfile_url'])
        elif verification_mode in [VerificationModes.PGP, VerificationModes.PGPCHECKSUMFILE] \
                and 'keyfile_url' in verification_data:
            file2_url = urlparse(verification_data['keyfile_url'])

        if file2_url is not None and filename_url.netloc != file2_url.netloc:
            msg_callback.echo("WARNING: URLs for the file being verified and verification data are on the same server!")

    @staticmethod
    def download_all_files(verification_mode, dir, filename_url, verification_data, msg_callback=None):
        """
        Downloads all files needed for processing

        :param verification_mode: verification mode being used
        :param dir: directory to download to
        :param filename_url: URL for the main file to be downloaded
        :param verification_data: parsed JSON containing verification data
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: one of VERIFICATION_MODES or None if none are found
        """
        # Main file is always downloaded
        click.echo('Downloading file: ' + filename_url)
        IcetrustCanaryUtils.download_file(filename_url, dir, FILENAME_FILE1, msg_callback=msg_callback)

        # Download comparison file
        if verification_mode == VerificationModes.COMPARE_FILES:
            # If the URLs of the two files are same, simply make a copy, otherwise download
            if filename_url == verification_data['file2_url']:
                if msg_callback:
                    msg_callback.echo("Both file URLs match, copying original file")
                shutil.copy(os.path.join(dir, FILENAME_FILE2), os.path.join(dir, FILENAME_FILE1))
            else:
                IcetrustCanaryUtils.download_file(verification_data['file2_url'], dir, FILENAME_FILE2,
                                                  msg_callback=msg_callback)

        # Download checksum files
        if verification_mode in [VerificationModes.CHECKSUMFILE,
                                 VerificationModes.PGPCHECKSUMFILE]:
            IcetrustCanaryUtils.download_file(verification_data['checksumfile_url'], dir, FILENAME_CHECKSUM,
                                              msg_callback=msg_callback)

        # Download signature files
        if verification_mode in [VerificationModes.PGP, VerificationModes.PGPCHECKSUMFILE]:
            IcetrustCanaryUtils.download_file(verification_data['signaturefile_url'], dir, FILENAME_SIGNATURE,
                                              msg_callback=msg_callback)

        # Download key file
        if verification_mode in [VerificationModes.PGP, VerificationModes.PGPCHECKSUMFILE]:
            if 'keyfile_url' in verification_data:
                IcetrustCanaryUtils.download_file(verification_data['keyfile_url'], dir,
                                                  os.path.join(dir, FILENAME_KEYS), msg_callback=msg_callback)


    @staticmethod
    def download_file(url, dir, filename, msg_callback=None):
        """
        Download the given file to the provided directory

        :param url: URL to download
        :param directory: directory to download to
        :param filename: filename to use for download
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: one of VERIFICATION_MODES or None if none are found
        """
        verbose = False
        if msg_callback:
            verbose = True
        download(url, os.path.join(dir, filename), progressbar=verbose, verbose=verbose)

    @staticmethod
    def extract_verification_data(config, mode, msg_callback=None):
        """
        Extracts verification data from config file

        :param config: parsed JSON config
        :param mode: verification mode
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: verification data or None if not found
        """
        verification_data = None
        if str(mode.value[0]) in config:
            verification_data = config[str(mode.value[0])]
        elif str(mode.value) in config:
            verification_data = config[str(mode.value)]

        if msg_callback and verification_data:
            msg_callback.echo("Verification data: " + str(verification_data))

        return verification_data

    @staticmethod
    def generate_json(config_data, verification_mode, verification_result, comparison_result, cmd_output, filename,
                      msg_callback=None):
        """
        Generates the JSON object for output file

        :param config_data: parsed JSON config
        :param verification_mode: verification mode used
        :param verification_result: verification result
        :param comparison_result: result of comparison against previous version
        :param cmd_output: command output
        :param filename: filename to calculate checksum value on
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: JSON object as string
        """
        # Calculate checksum first
        checksum_value = filehash.FileHash('sha256').hash_file(filename=filename)

        # Construct JSON
        output_obj = dict()
        output_obj['name'] = config_data['name']
        output_obj['url'] = config_data['url']
        output_obj['timestamp'] = datetime.now(tzlocal.get_localzone()).isoformat()
        output_obj['filename_url'] = config_data['filename_url']
        output_obj['checksum_value'] = checksum_value
        output_obj['verification_mode'] = verification_mode.name.lower()
        output_obj['verified'] = verification_result

        if comparison_result is not None:
            output_obj['previous_version_matched'] = comparison_result

        output_obj['output'] = ', '.join(cmd_output)
        json_data = json.dumps(output_obj, indent=4)

        if msg_callback:
            msg_callback.echo("--- JSON output ---")
            msg_callback.echo(json_data)
        return json_data

    @staticmethod
    def get_verification_mode(config, msg_callback=None):
        """
        Extracts the correct verification mode from config file

        :param config: parsed JSON config
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: one of VERIFICATION_MODES or None if none are found
        """
        for mode in VerificationModes:
            if str(mode.value[0]) in config or str(mode.value) in config:
                return mode

        return None

    @staticmethod
    def get_algorithm(verification_data, msg_callback=None):
        """
        Gets algorithm to be used based on verification data

        :param verification_data: parsed JSON containing verification data
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: returns algorithm to be used
        """
        algorithm = DEFAULT_HASH_ALGORITHM
        if 'algorithm' in verification_data:
            algorithm = verification_data['algorithm']

        if msg_callback:
            msg_callback.echo("Using algorithm: " + algorithm)

        return algorithm

    @staticmethod
    def import_key_material(gpg, dir, verification_data, cmd_output=None, msg_callback=None):
        """
        Import keys if needed

        :param verification_mode: verification mode being used
        :param dir: directory to download to
        :param filename_url: URL for the main file to be downloaded
        :param verification_data: parsed JSON containing verification data
        :param cmd_output: command output
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: True if succesful, False if not, None if skipped
        """
        keyfile_path = None
        if 'keyfile_url' in verification_data:
            keyfile_path = os.path.join(dir, FILENAME_KEYS)

        # Do the actual import
        import_result = IcetrustUtils.pgp_import_keys(gpg, keyfile=keyfile_path,
                                                      keyid=None if keyfile_path else verification_data['keyid'],
                                                      keyserver=None if keyfile_path else verification_data['keyserver'],
                                                      cmd_output=cmd_output,
                                                      msg_callback=msg_callback)
        return import_result

    @staticmethod
    def validate_config_file(config_file, msg_callback=None):
        """
        Validates config file against the schema

        :param config: config file stream
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: returns parsed JSON if valid, None if not
        """
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        config_data = json.load(config_file)
        try:
            jsonschema.validators.validate(instance=config_data, schema=schema_data,
                                           format_checker=jsonschema.draft7_format_checker)
        except jsonschema.exceptions.ValidationError as err:
            if msg_callback:
                msg_callback.echo("Config file is not properly formatted!")
                msg_callback.echo(err.message)
            return None

        return config_data
