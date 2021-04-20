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
from pathlib import Path
import sys, tempfile

import click
from filehash import FileHash
import gnupg

# Default hash algorithm to use for checksums
DEFAULT_HASH_ALGORITHM = 'sha256'


class IcecrustUtils(object):
    """Various utility functions, split off from the main class for ease of unit testing"""

    @staticmethod
    def get_version():
        """Gets the current version"""
        return "0.1.0"


    @staticmethod
    def compare_files(file1, file2, verbose=False):
        """
        Compare files using SHA-256 hashes

        :param file1: First file to compare
        :param file2: Second file to compare
        :param verbose: if True, output additional information
        :return: True if matches, False if doesn't match
        """
        # Calculate the hashes
        hasher = FileHash(DEFAULT_HASH_ALGORITHM)
        try:
            file1_hash = hasher.hash_file(filename=file1)
            file2_hash = hasher.hash_file(filename=file2)
        except FileNotFoundError as err:
            if verbose:
                click.echo(err)
            return False

        # Output additional information if needed
        if verbose:
            click.echo('File1 checksum: ' + file1_hash)
            click.echo('File2 checksum: ' + file2_hash)

        # Compare the checksums and return the result
        if file1_hash == file2_hash:
            return True
        else:
            return False

    @staticmethod
    def pgpverify(filename, signaturefile, verbose, temp_dir=None, keyfile=None, keyid=None, keyserver=None):
        # Setup GPG
        if temp_dir is None:
            gpg_home = tempfile.TemporaryDirectory()
            gpg = gnupg.GPG(gnupghome=gpg_home.name)
        else:
            gpg = gnupg.GPG(gnupghome=temp_dir)

        # Import keys from file or server
        if keyfile:
            keydata = Path(keyfile).read_text()
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


    @staticmethod
    def verify_checksum(filename, algorithm, checksum=None, checksumfile=None, verbose=False):
        """
        Calculates a filename hash and compares against the provided checksum or checksums file

        :param filename: Filename used to calculate the hash
        :param checksum: Checksum value
        :param checksumfile: Filename of the file containing checksums, follows the format from shasum
        :param algorithm: Algorithm to use for hashing
        :param verbose: if True, output additional output
        :return: True if matches, False if doesn't match
        """
        # Calculate the hash
        try:
            calculated_hash = FileHash(algorithm).hash_file(filename=filename)
        except FileNotFoundError as err:
            if verbose:
                click.echo(err)
            return False

        # Output additional information if needed
        if verbose:
            click.echo('Algorithm: ' + algorithm)
            click.echo('File hash: ' + calculated_hash)

        # Compare the checksums and return the result
        if checksum:
            return calculated_hash == checksum.lower().strip()
        else:
            try:
                checksums_content = Path(checksumfile).read_text()
            except (FileNotFoundError, TypeError) as err:
                if verbose:
                    click.echo(err)
                return False
            return calculated_hash in checksums_content

