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
from click.testing import CliRunner

from icecrust.cli import cli
from icecrust.utils import IcecrustUtils
from test_utils import TEST_DIR, FILE1_HASH, FILE2_HASH


# Tests for "--version" option
class TestCliVersion(object):
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert result.output == 'icecrust, version ' + IcecrustUtils.get_version() + '\n'


# Tests for "compare_files" option
class TestCliCompareFiles(object):
    def test_valid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt'])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', '--verbose', TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt'])
        assert result.exit_code == 0
        assert result.output == \
               'File1 checksum: ' + FILE1_HASH + '\n' + \
               'File2 checksum: ' + FILE1_HASH + '\n' + \
               'File verified\n'

    def test_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', TEST_DIR + 'file1.txt', TEST_DIR + 'file2.txt'])
        assert result.exit_code == -1
        assert result.output == 'ERROR: File cannot be verified!\n'

    def test_invalid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', '--verbose', TEST_DIR + 'file1.txt', TEST_DIR + 'file2.txt'])
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
        result = runner.invoke(cli, ['compare_files', TEST_DIR + 'file1.txt'])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILE2'" in result.output

    def test_invalid_file1_doesnt_exist(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', 'foobar.txt'])
        assert result.exit_code == 2
        assert "Error: Invalid value for 'FILE1': File 'foobar.txt' does not exist." in result.output

    def test_invalid_file2_doesnt_exist(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['compare_files', TEST_DIR + 'file1.txt', 'foobar.txt'])
        assert result.exit_code == 2
        assert "Error: Invalid value for 'FILE2': File 'foobar.txt' does not exist." in result.output


# Tests for "verify_via_checksum" option
class TestCliVerifyChecksum(object):
    def test_valid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum', '--algorithm', 'sha256',
                                     TEST_DIR + 'file1.txt', '--checksum_value', FILE1_HASH])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_default_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum', TEST_DIR + 'file1.txt', '--checksum_value', FILE1_HASH])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum',
                                     '--verbose', TEST_DIR + 'file1.txt', '--checksum_value', FILE1_HASH])
        assert result.exit_code == 0
        assert result.output == 'Algorithm: sha256\n' + \
               'File hash: ' + FILE1_HASH + '\n' + \
               'File verified\n'

    def test_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum', TEST_DIR + 'file1.txt', '--checksum_value', FILE2_HASH])
        assert result.exit_code == -1
        assert result.output == 'ERROR: File cannot be verified!\n'

    def test_invalid_wrong_algorithm_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum', '--algorithm', 'sha1', '--verbose',
                                     TEST_DIR + 'file1.txt', '--checksum_value', FILE2_HASH])
        assert result.exit_code == -1
        assert result.output == 'Algorithm: sha1\n' + \
               'File hash: 4045ed3c779e3b27760e4da357279508a8452dcb\n' + \
               'ERROR: File cannot be verified!\n'

    def test_invalid_bad_arguments_invalid_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum', '--algorithm', 'foobar',
                                     TEST_DIR + 'file1.txt', '--checksum_value', FILE2_HASH])
        assert result.exit_code == 2
        assert "Error: Invalid value for '--algorithm': invalid choice: foobar." in result.output

    def test_invalid_bad_arguments_missing_checksum(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum', TEST_DIR + 'file1.txt'])
        assert result.exit_code == 2
        assert "Error: Missing option '--checksum_value'." in result.output

    def test_invalid_bad_arguments_missing_filename(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksum', '--checksum_value', FILE1_HASH])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILENAME'." in result.output


# Tests for "verify_via_checksumfile" option
class TestCliVerifyChecksumFile(object):
    def test_valid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile', '--algorithm', 'sha256',
                                     TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt.SHA256SUMS'])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_default_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile',
                                     TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt.SHA256SUMS'])
        assert result.exit_code == 0
        assert result.output == 'File verified\n'

    def test_valid_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile', '--verbose',
                                     TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt.SHA256SUMS'])
        assert result.exit_code == 0
        assert result.output == 'Algorithm: sha256\n' + \
               'File hash: ' + FILE1_HASH + '\n' + \
               'File verified\n'

    def test_invalid(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile', TEST_DIR + 'file1.txt', TEST_DIR + 'file2.txt'])
        assert result.exit_code == -1
        assert result.output == 'ERROR: File cannot be verified!\n'

    def test_invalid_wrong_algorithm_verbose(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile', '--algorithm', 'sha1', '--verbose',
                                     TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt.SHA256SUMS'])
        assert result.exit_code == -1
        assert result.output == 'Algorithm: sha1\n' + \
               'File hash: 4045ed3c779e3b27760e4da357279508a8452dcb\n' + \
               'ERROR: File cannot be verified!\n'

    def test_invalid_bad_arguments_invalid_algorithm(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile', '--algorithm', 'foobar',
                                     TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt.SHA256SUMS'])
        assert result.exit_code == 2
        assert "Error: Invalid value for '--algorithm': invalid choice: foobar." in result.output

    def test_invalid_bad_arguments_missing_checksumfile(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile', TEST_DIR + 'file1.txt'])
        assert result.exit_code == 2
        assert "Error: Missing argument 'CHECKSUMFILE'." in result.output

    def test_invalid_bad_arguments_missing_filename(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['verify_via_checksumfile'])
        assert result.exit_code == 2
        assert "Error: Missing argument 'FILENAME'." in result.output
