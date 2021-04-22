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
import re, tempfile

import gnupg
import pytest

from icecrust.utils import DEFAULT_HASH_ALGORITHM, IcecrustUtils

# Directory with test data
TEST_DIR = 'test_data/'
FILE1_HASH = '07fe4d4a25718241af145a93f890eb5469052e251d199d173bd3bd50c3bb4da2'

# Tests for utils.get_version()
class TestUtilsGetVersion(object):
    def test_format_valid(self):
        pattern = re.compile(r'^(\d+\.)?(\d+\.)?(\*|\d+)$')
        assert pattern.match(IcecrustUtils.get_version()) is not None


# Tests for utils.compare_files()
class TestUtilsCompareFiles(object):
    def test_doesnt_exists_file1(self):
        assert IcecrustUtils.compare_files(False, TEST_DIR + 'foobar.txt', TEST_DIR + 'file1.txt') is False

    def test_doesnt_exists_file2(self):
        assert IcecrustUtils.compare_files(False, TEST_DIR + 'file1.txt', TEST_DIR + 'file2.txt') is False

    def test_doesnt_exists_all_files(self):
        assert IcecrustUtils.compare_files(False, TEST_DIR + 'foobar1.txt', TEST_DIR + 'foobar2.txt') is False

    def test_valid(self):
        assert IcecrustUtils.compare_files(False, TEST_DIR + 'file1.txt', TEST_DIR + 'file1.txt') is True

    def test_invalid1(self):
        assert IcecrustUtils.compare_files(False, TEST_DIR + 'file1.txt', TEST_DIR + 'file2.txt') is False

    def test_invalid2(self):
        assert IcecrustUtils.compare_files(False, TEST_DIR + 'file2.txt', TEST_DIR + 'file1.txt') is False


# Tests for utils.pgp_import_keys()
class TestUtilsPgpImportKeys(object):
    def test_valid(self):
        gpg = IcecrustUtils.pgp_init()
        assert IcecrustUtils.pgp_import_keys(True, gpg, keyfile=TEST_DIR + 'pgp_keys.txt') is True


# Tests for utils.pgp_init()
class TestUtilsPgpInit(object):
    def test_invalid_bad_dir(self):
        with pytest.raises(ValueError):
            IcecrustUtils.pgp_init("foobar")

    def test_valid(self):
        assert type(IcecrustUtils.pgp_init()) is gnupg.GPG

    def test_valid_with_dir(self):
        temp_dir = tempfile.TemporaryDirectory()
        assert type(IcecrustUtils.pgp_init(gpg_home_dir=temp_dir.name)) is gnupg.GPG


# Tests for utils.verify_checksum()
class TestUtilsVerifyChecksum(object):
    def test_doesnt_exists_file(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'foobar.txt', DEFAULT_HASH_ALGORITHM,
                                             checksumfile=TEST_DIR + 'file1.txt.SHA256SUMS') is False

    def test_doesnt_exists_checksum_file(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', DEFAULT_HASH_ALGORITHM,
                                             checksumfile=TEST_DIR + 'foobar') is False

    def test_valid_checksumfile(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', DEFAULT_HASH_ALGORITHM,
                                             checksumfile=TEST_DIR + 'file1.txt.SHA256SUMS') is True

    def test_valid_checksum(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', DEFAULT_HASH_ALGORITHM,
                                             checksum=FILE1_HASH) is True

    def test_valid_checksum_and_invalid_file(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', DEFAULT_HASH_ALGORITHM,
                                             checksum=FILE1_HASH, checksumfile=TEST_DIR + 'foobar') is True

    def test_valid_checksum_uppercase(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', DEFAULT_HASH_ALGORITHM,
                                             checksum=FILE1_HASH.upper()) is True

    def test_valid_checksum_whitespace(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', DEFAULT_HASH_ALGORITHM,
                                             checksum=' ' + FILE1_HASH + ' ') is True

    def test_invalid1_checksumfile(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt.SHA256SUMS', DEFAULT_HASH_ALGORITHM,
                                             checksumfile=TEST_DIR + 'file1.txt') is False

    def test_invalid2_checksumfile(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file2.txt', DEFAULT_HASH_ALGORITHM,
                                             checksumfile=TEST_DIR + 'file1.txt.SHA256SUMS') is False

    def test_invalid_algorithm_checksum1(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', 'md5',
                                             checksum=FILE1_HASH) is False

    def test_invalid_algorithm_checksum2(self):
        with pytest.raises(ValueError):
            IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', 'rc4', checksum=FILE1_HASH) is False

    def test_invalid_algorithm_checksumfile1(self):
        assert IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', 'md5',
                                             checksumfile=TEST_DIR + 'file1.txt.SHA256SUMS') is False

    def test_invalid_algorithm_checksumfile2(self):
        with pytest.raises(ValueError):
            IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', 'rc4', checksumfile=TEST_DIR + 'file1.txt.SHA256SUMS') is False

    def test_invalid_missing_arguments(self):
        with pytest.raises(ValueError):
            IcecrustUtils.verify_checksum(False, TEST_DIR + 'file1.txt', 'rc4') is False
