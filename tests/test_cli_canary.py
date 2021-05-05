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
import pytest

from icetrust.cli import cli
from test_utils import TEST_DIR


# Tests for "canary" command()
class TestCanary(object):
    @pytest.mark.network
    def test_compare_invalid(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ['canary', os.path.join(TEST_DIR, 'canary_input', 'compare_pnpm_input.json')])
        assert result.exit_code == -1
        assert result.output == 'Using verification mode: COMPARE_FILES\n' + \
               'Downloading file: https://get.pnpm.io/v6.js\n' + \
               'ERROR: File cannot be verified!\n'

    @pytest.mark.network
    def test_checksum_valid(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ['canary', os.path.join(TEST_DIR, 'canary_input', 'checksum_pnpm_input.json')])
        assert result.exit_code == 0
        assert result.output == 'Using verification mode: VERIFY_VIA_CHECKSUM\n' + \
               'Downloading file: https://get.pnpm.io/v6.js\n' + \
               'File verified\n'

    @pytest.mark.network
    def test_checksumfile_valid(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ['canary', os.path.join(TEST_DIR, 'canary_input', 'checksumfile_pnpm_input.json')])
        assert result.exit_code == 0
        assert result.output == 'Using verification mode: VERIFY_VIA_CHECKSUMFILE\n' + \
               'Downloading file: https://get.pnpm.io/v6.js\n' + \
               'File verified\n'

    @pytest.mark.network
    def test_pgp_valid(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli, ['canary', os.path.join(TEST_DIR, 'canary_input', 'pgp_pnpm_input.json')])
        assert result.exit_code == 0
        assert result.output == 'Using verification mode: VERIFY_VIA_PGP\n' + \
               'Downloading file: https://get.pnpm.io/SHASUMS256.txt\n' + \
               'File verified\n'

    @pytest.mark.network
    def test_pgpchecksumfile_valid(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(cli,
                               ['canary', os.path.join(TEST_DIR, 'canary_input', 'pgpchecksumfile_pnpm_input.json')])
        assert result.exit_code == 0
        assert result.output == 'Using verification mode: VERIFY_VIA_PGPCHECKSUMFILE\n' + \
               'Downloading file: https://get.pnpm.io/v6.js\n' + \
               'File verified\n'
