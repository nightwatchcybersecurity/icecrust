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
import os

from click.testing import CliRunner

from icetrust.cli import cli
from icetrust.utils import IcetrustUtils
from test_utils import TEST_DIR, FILE1_HASH, FILE2_HASH


# Tests for "--version" option
class TestCliVersion(object):
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert result.output == 'icetrust, version ' + IcetrustUtils.get_version() + '\n'


# Tests for "compare_files" option
class TestCliCompareFiles(object):
    def test_valid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt')])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', '--verbose', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt')])
        assert result.exit_code == 0
        assert result.output == \
               'File1 checksum: ' + FILE1_HASH + '\n' + \
               'File2 checksum: ' + FILE1_HASH + '\n' + \
               'File verified\n'

    def test_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file2.txt')])
        assert result.exit_code == -1
        assert result.output == 'ERROR: File cannot be verified!\n'

    def test_invalid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', '--verbose', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file2.txt')])
        assert result.exit_code == -1
        assert result.output == \
               'File1 checksum: ' + FILE1_HASH + '\n' + \
               'File2 checksum: ' + FILE2_HASH + '\n' + \
               'ERROR: File cannot be verified!\n'

    def test_invalid_arguments_missing_file1(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files'])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILE1'" in result.output

    def test_invalid_arguments_missing_file2(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', os.path.join(TEST_DIR, 'file1.txt')])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILE2'" in result.output

    def test_invalid_file1_doesnt_exist(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', 'foobar.txt'])
        assert result.exit_code == 2
        assert "Error: Invalid value for 'FILE1': File 'foobar.txt' does not exist." in result.output

    def test_invalid_file2_doesnt_exist(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', os.path.join(TEST_DIR, 'file1.txt'), 'foobar.txt'])
        assert result.exit_code == 2
        assert "Error: Invalid value for 'FILE2': File 'foobar.txt' does not exist." in result.output


# Tests for "checksum" option
class TestCliVerifyChecksum(object):
    def test_valid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksum', '--algorithm', 'sha256',
                                     os.path.join(TEST_DIR, 'file1.txt'), FILE1_HASH])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_default_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksum', os.path.join(TEST_DIR, 'file1.txt'), FILE1_HASH])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksum',
                                     '--verbose', os.path.join(TEST_DIR, 'file1.txt'), FILE1_HASH])
        assert result.exit_code == 0
        assert result.output == 'Algorithm: sha256\n' + \
               'File hash: ' + FILE1_HASH + '\n' + \
               'File verified\n'

    def test_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksum', os.path.join(TEST_DIR, 'file1.txt'), FILE2_HASH])
        assert result.exit_code == -1
        assert result.output == 'ERROR: File cannot be verified!\n'

    def test_invalid_wrong_algorithm_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksum', '--algorithm', 'sha1', '--verbose',
                                     os.path.join(TEST_DIR, 'file1.txt'), FILE2_HASH])
        assert result.exit_code == -1
        assert result.output == 'Algorithm: sha1\n' + \
               'File hash: 4045ed3c779e3b27760e4da357279508a8452dcb\n' + \
               'ERROR: File cannot be verified!\n'

    def test_invalid_bad_arguments_invalid_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksum', '--algorithm', 'foobar',
                                     os.path.join(TEST_DIR, 'file1.txt'), FILE2_HASH])
        assert result.exit_code == 2
        assert "Error: Invalid value for '--algorithm'" in result.output


# Tests for "checksumfile" option
class TestCliVerifyChecksumFile(object):
    def test_valid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile', '--algorithm', 'sha256',
                                     os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS')])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_default_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile',
                                     os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS')])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile', '--verbose',
                                     os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS')])
        assert result.exit_code == 0
        assert result.output == 'Algorithm: sha256\n' + \
               'File hash: ' + FILE1_HASH + '\n' + \
               'File verified\n'

    def test_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file2.txt')])
        assert result.exit_code == -1
        assert result.output == 'ERROR: File cannot be verified!\n'

    def test_invalid_wrong_algorithm_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile', '--algorithm', 'sha1', '--verbose',
                                     os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS')])
        assert result.exit_code == -1
        assert result.output == 'Algorithm: sha1\n' + \
               'File hash: 4045ed3c779e3b27760e4da357279508a8452dcb\n' + \
               'ERROR: File cannot be verified!\n'

    def test_invalid_bad_arguments_invalid_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile', '--algorithm', 'foobar',
                                     os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS')])
        assert result.exit_code == 2
        assert "Error: Invalid value for '--algorithm'" in result.output

    def test_invalid_bad_arguments_missing_checksumfile(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile', os.path.join(TEST_DIR, 'file1.txt')])
        assert result.exit_code == 2
        assert "Error: Missing argument 'CHECKSUMFILE'." in result.output

    def test_invalid_bad_arguments_missing_filename(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['checksumfile'])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILENAME'." in result.output


# Tests for "pgp" option
class TestCliVerifyPgp(object):
    def test_invalid_bad_arguments_missing_filename(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgp'])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILENAME'." in result.output

    def test_invalid_bad_arguments_missing_signaturefile(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgp', os.path.join(TEST_DIR, 'file1.txt')])
        assert result.exit_code == 2
        assert "Error: Missing argument 'SIGNATUREFILE'." in result.output

    def test_invalid_bad_arguments_missing_keys(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgp', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.sig')])
        assert result.exit_code == 2
        assert "ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!\n" in result.output

    def test_invalid_bad_arguments_keyid_without_keyserver(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgp', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.sig'),
                                     '--keyid', 'keyid'])
        assert result.exit_code == 2
        assert "ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!\n" in result.output

    def test_invalid_bad_arguments_keyserver_without_keyid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgp', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.sig'),
                                     '--keyserver', 'keyserver'])
        assert result.exit_code == 2
        assert "ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!\n" in result.output


# Tests for "pgpchecksumfile" option
class TestCliVerifyPgpChecksumFile(object):
    def test_invalid_bad_arguments_missing_filename(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgpchecksumfile'])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILENAME'." in result.output

    def test_invalid_bad_arguments_missing_checksumfile(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgpchecksumfile', os.path.join(TEST_DIR, 'file1.txt')])
        assert result.exit_code == 2
        assert "Error: Missing argument 'CHECKSUMFILE'." in result.output

    def test_invalid_bad_arguments_missing_signaturefile(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgpchecksumfile', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS')])
        assert result.exit_code == 2
        assert "Error: Missing argument 'SIGNATUREFILE'." in result.output

    def test_invalid_bad_arguments_missing_keys(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgpchecksumfile', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS.sig')])
        assert result.exit_code == 2
        assert "ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!\n" in result.output

    def test_invalid_bad_arguments_keyid_without_keyserver(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgpchecksumfile', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS.sig')])
        assert result.exit_code == 2
        assert "ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!\n" in result.output

    def test_invalid_bad_arguments_keyserver_without_keyid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['pgpchecksumfile', os.path.join(TEST_DIR, 'file1.txt'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS'),
                                     os.path.join(TEST_DIR, 'file1.txt.SHA256SUMS.sig')])
        assert result.exit_code == 2
        assert "ERROR: Either '--keyfile' or '--keyid/--keyserver' parameters must be set!\n" in result.output
