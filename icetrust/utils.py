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
from pathlib import Path
import tempfile

import click, filehash, gnupg

# Default hash algorithm to use for checksums
DEFAULT_HASH_ALGORITHM = 'sha256'


# Helper objects
class MsgCallback(object):
    """Used for message callback methods"""
    def __init__(self):
        self.messages = []

    def echo(self, message):
        """Echos the message to stdout"""
        self.messages.append(message)


class IcetrustUtils(object):
    """Various utility functions, split off from the main class for ease of unit testing"""
    @staticmethod
    def get_version():
        """Gets the current version"""
        return "0.1.4"

    @staticmethod
    def compare_files(file1, file2, msg_callback=None, cmd_output=None):
        """
        Compare files by calculating and comparing SHA-256 checksums

        :param file1: First file to compare
        :param file2: Second file to compare
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :param cmd_output: Additional data to be used for JSON output
        :return: True if matches, False if doesn't match
        """
        # Calculate the checksums
        hasher = filehash.FileHash(DEFAULT_HASH_ALGORITHM)
        try:
            file1_hash = hasher.hash_file(filename=file1)
            file2_hash = hasher.hash_file(filename=file2)
        except FileNotFoundError as err:
            if msg_callback:
                msg_callback.echo(str(err))
            return False

        # Output additional information if needed
        if msg_callback:
            msg_callback.echo('File1 checksum: ' + file1_hash)
            msg_callback.echo('File2 checksum: ' + file2_hash)

        # Compare the checksums and return the result
        if file1_hash == file2_hash:
            return True
        else:
            if cmd_output is not None:
                cmd_output.append('File1 checksum: ' + file1_hash)
                cmd_output.append('File2 checksum: ' + file2_hash)
            return False

    @staticmethod
    def pgp_import_keys(gpg, msg_callback=None, cmd_output=None, keyfile=None, keyid=None, keyserver=None):
        """
        Imports GPG keys into the gpg instance

        :param gpg: initialized gpg instance
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :param cmd_output: Additional data to be used for JSON output
        :param keyfile: file containing PGP keys to be imported
        :param keyid: ID of the key to be imported from a key server
        :param keyserver: domain name of the key server to be used
        :return: True if import was successful, False otherwise
        """
        # Check input parameters
        if keyfile is None and keyid is None and keyserver is None:
            raise ValueError("Either 'keyfile' or 'keyid/keyserver' parameters must be set!")
        elif keyfile is None and (keyid is None or keyserver is None):
            raise ValueError("Both 'keyid' and 'keyserver' parameters must be set!")

        # Import keys from file or server
        if keyfile:
            try:
                keydata = Path(keyfile).read_text()
            except FileNotFoundError as err:
                if msg_callback:
                    msg_callback.echo(str(err))
                return False

            import_result = gpg.import_keys(keydata)
        else:
            import_result = gpg.recv_keys(keyserver, keyid)

        if msg_callback:
            msg_callback.echo('--- Results of key import ---\n')
            msg_callback.echo(import_result.stderr)

        if cmd_output is not None:
            cmd_output.append(import_result.stderr)

        # Return results
        if import_result.imported == 0:
            return False
        else:
            return True

    @staticmethod
    def pgp_init(gpg_home_dir=None, verbose=False):
        """
        Initializes the GPG object

        :param gpg_home_dir: directory to use for GPG home, if not passed, temporary directory will be used
        :param verbose: whether GPG should output additional data, used for debugging
        :return: initialized gpg instance
        """
        # Setup GPG
        if gpg_home_dir is None:
            temp_dir = tempfile.TemporaryDirectory()
            return gnupg.GPG(gnupghome=str(temp_dir.name), verbose=verbose)
        else:
            return gnupg.GPG(gnupghome=str(gpg_home_dir), verbose=verbose)

    @staticmethod
    def pgp_verify(gpg, filename, signaturefile, msg_callback=None, cmd_output=None):
        """
        Verifies a file against its PGP signature

        :param gpg: initialized gpg instance
        :param filename: file to be verified
        :param signaturefile: file containing the PGP signature
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :param cmd_output: Additional data to be used for JSON output
        :return: True if verification was successful, False otherwise
        """
        # Open signature file
        try:
            signature = open(signaturefile, "rb")
        except FileNotFoundError as err:
            if msg_callback:
                msg_callback.echo(str(err))
            return False

        # Attempt to verify
        verification_result = gpg.verify_file(signature, filename)
        if msg_callback:
            msg_callback.echo('\n--- Results of verification ---')
            msg_callback.echo(verification_result.stderr)

        # Return results
        if verification_result.status == 'signature valid':
            return True
        else:
            if cmd_output is not None:
                cmd_output.append(verification_result.stderr)
            return False

    @staticmethod
    def process_verbose_flag(verbose):
        """
        Return message callback object to be used for output, usually click

        :param verbose: if True, return an object to be used for output
        :return: message callback object
        """
        if verbose:
            return click
        else:
            return False

    @staticmethod
    def verify_checksum(filename, algorithm, msg_callback=None, cmd_output=None,
                        checksum_value=None, checksumfile=None):
        """
        Calculates a filename hash and compares against the provided checksum or checksums file

        :param filename: Filename used to calculate the hash
        :param algorithm: Algorithm to use for hashing
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :param cmd_output: Additional data to be used for JSON output
        :param checksum_value: Checksum value
        :param checksumfile: Filename of the file containing checksums, follows the format from shasum
        :return: True if matches, False if doesn't match
        """
        # Check algorithm for valid values
        if algorithm not in filehash.SUPPORTED_ALGORITHMS:
            raise ValueError('Unsupported algorithm value')

        # Make sure either checksum or checksumfile arguments are set
        if checksum_value is None and checksumfile is None:
            raise ValueError('Either checksum_value or checksumfile arguments must be set')

        # Calculate the hash
        try:
            calculated_hash = filehash.FileHash(algorithm).hash_file(filename=filename)
        except FileNotFoundError as err:
            if msg_callback:
                msg_callback.echo(str(err))
            return False

        # Output additional information if needed
        if msg_callback:
            msg_callback.echo('Algorithm: ' + algorithm)
            msg_callback.echo('File hash: ' + calculated_hash)

        # Compare the checksums and return the result
        if checksum_value:
            if calculated_hash == checksum_value.lower().strip():
                return True
            else:
                if cmd_output is not None:
                    cmd_output.append('Algorithm: ' + algorithm)
                    cmd_output.append('File checksum: ' + calculated_hash)
                    cmd_output.append('Checksum to check against: ' + checksum_value)
                return False
        else:
            try:
                checksums_content = str(Path(checksumfile).read_bytes())
            except (FileNotFoundError, TypeError) as err:
                if msg_callback:
                    msg_callback.echo(str(err))
                return False

            # Process verification results
            if calculated_hash in checksums_content:
                return True
            else:
                if cmd_output is not None:
                    cmd_output.append('Algorithm: ' + algorithm)
                    cmd_output.append('File checksum: ' + calculated_hash)
                    cmd_output.append('No match found in checksum file')
                return False
