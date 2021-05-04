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
import json

import jsonschema, pytest

from icecrust.utils_canary import\
    VerificationModes, CANARY_INPUT_SCHEMA, CANARY_OUTPUT_SCHEMA, DEFAULT_HASH_ALGORITHM
from icecrust.utils_canary import IcecrustCanaryUtils

from test_utils import mock_msg_callback, TEST_DIR


# Tests for misc utils methods
class TestCanaryUtils(object):
    def test_const_verification_modes(self):
        assert len(VerificationModes) == 5
        assert VerificationModes['COMPARE_FILES'] is not None
        assert VerificationModes['VERIFY_VIA_CHECKSUM'] is not None
        assert VerificationModes['VERIFY_VIA_CHECKSUMFILE'] is not None
        assert VerificationModes['VERIFY_VIA_PGP'] is not None
        assert VerificationModes['VERIFY_VIA_PGPCHECKSUMFILE'] is not None

    def test_canary_schemas_valid(self):
        input_schema = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        output_schema = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        jsonschema.Draft7Validator.check_schema(input_schema)
        jsonschema.Draft7Validator.check_schema(output_schema)

    def test_input_schema_valid_file1(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_input/compare_pnpm_input.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_file2(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_input/checksum_pnpm_input.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_file3(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_input/checksumfile_pnpm_input.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_file4(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_input/pgp_pnpm_input.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_file5(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_input/pgpchecksumfile_pnpm_input.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_invalid_file(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_output/compare_pnpm_output_verified.json', 'r'))
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                           format_checker=jsonschema.draft7_format_checker)

    def test_output_schema_valid_file(self):
        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_output/compare_pnpm_output_verified.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_output_schema_invalid_file(self):
        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary_input/compare_pnpm_input.json', 'r'))
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                           format_checker=jsonschema.draft7_format_checker)


# Tests for extract_verification_data method
class TestExtractVerificationData(object):
    def test_valid(self):
        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/compare_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES) is not None

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/checksum_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.VERIFY_VIA_CHECKSUM) is not None

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/checksumfile_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.VERIFY_VIA_CHECKSUMFILE)\
               is not None

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/pgp_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.VERIFY_VIA_PGP) is not None

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/pgpchecksumfile_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE)\
               is not None

    def test_valid_verbose(self, mock_msg_callback):
        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/compare_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES,
                                                             msg_callback=mock_msg_callback) is not None
        assert len(mock_msg_callback.messages) == 1
        assert mock_msg_callback.messages[0] ==\
               "Verification data: {'file2_url': 'https://cdn.jsdelivr.net/npm/pnpm@6.2.1/dist/pnpm.cjs'}"

    def test_invalid(self):
        config = dict()
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES) is None

    def test_invalid_verbose(self, mock_msg_callback):
        config = dict()
        assert IcecrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES,
                                                             msg_callback=mock_msg_callback) is None
        assert len(mock_msg_callback.messages) == 0


# Tests for generate_json method
class TestGenerateJson(object):
    def test_valid(self):
        config_data = dict()
        config_data['name'] = 'foobar1'
        config_data['url'] = 'https://www.example.com'
        config_data['filename_url'] = 'https://www.example.com/file.sh'
        verification_mode = VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE
        verified_result = False
        cmd_output = ['foobar2', 'foobar3']
        json_raw = IcecrustCanaryUtils.generate_json(config_data, verification_mode, verified_result, cmd_output)
        json_parsed = json.loads(json_raw)

        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        jsonschema.validators.validate(instance=json_parsed, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

        assert(json_parsed['name']) == config_data['name']
        assert(json_parsed['url']) == config_data['url']
        assert(json_parsed['filename_url']) == config_data['filename_url']
        assert(json_parsed['verification_mode']) == VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE.value
        assert (json_parsed['verified']) == verified_result
        assert (json_parsed['output']) == ', '.join(cmd_output)


# Tests for get_verification_mode method
class TestGetVerificationMode(object):
    def test_valid(self):
        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/compare_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.get_verification_mode(config) == VerificationModes.COMPARE_FILES

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/checksum_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.get_verification_mode(config) == VerificationModes.VERIFY_VIA_CHECKSUM

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/checksumfile_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.get_verification_mode(config) == VerificationModes.VERIFY_VIA_CHECKSUMFILE

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/pgp_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.get_verification_mode(config) == VerificationModes.VERIFY_VIA_PGP

        config = IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/pgpchecksumfile_pnpm_input.json', 'r'))
        assert IcecrustCanaryUtils.get_verification_mode(config) == VerificationModes.VERIFY_VIA_PGPCHECKSUMFILE

    def test_invalid(self):
        config = dict()
        assert IcecrustCanaryUtils.get_verification_mode(config) is None


# Tests for get_algorithm method
class TestGetAlgorithm(object):
    def test_valid(self):
        verification_data = dict()
        verification_data['algorithm'] = 'sha1'
        assert IcecrustCanaryUtils.get_algorithm(verification_data) == 'sha1'

    def test_valid_default(self):
        verification_data = dict()
        assert IcecrustCanaryUtils.get_algorithm(verification_data) == DEFAULT_HASH_ALGORITHM

    def test_valid_verbose(self, mock_msg_callback):
        verification_data = dict()
        verification_data['algorithm'] = 'sha1'
        assert IcecrustCanaryUtils.get_algorithm(verification_data, msg_callback=mock_msg_callback) == 'sha1'
        assert len(mock_msg_callback.messages) == 1
        assert mock_msg_callback.messages[0] == "Using algorithm: sha1"

    def test_valid_default_verbose(self, mock_msg_callback):
        verification_data = dict()
        assert IcecrustCanaryUtils.get_algorithm(verification_data, msg_callback=mock_msg_callback)\
               == DEFAULT_HASH_ALGORITHM
        assert len(mock_msg_callback.messages) == 1
        assert mock_msg_callback.messages[0] == "Using algorithm: sha256"


# Tests for validate_config_file method
class TestValidateConfigFile(object):
    def test_valid(self):
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/compare_pnpm_input.json', 'r')) \
               is not None
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/checksum_pnpm_input.json', 'r')) \
               is not None
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/checksumfile_pnpm_input.json', 'r')) \
               is not None
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/pgp_pnpm_input.json', 'r')) \
               is not None
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/pgpchecksumfile_pnpm_input.json', 'r')) \
               is not None

    def test_valid_verbose(self, mock_msg_callback):
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_input/compare_pnpm_input.json', 'r'),
                                                        msg_callback=mock_msg_callback) is not None
        assert len(mock_msg_callback.messages) == 0

    def test_invalid(self):
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_output/compare_pnpm_output_verified.json', 'r')) \
               is None

    def test_invalid_verbose(self, mock_msg_callback):
        assert IcecrustCanaryUtils.validate_config_file(open(TEST_DIR + 'canary_output/compare_pnpm_output_verified.json', 'r'),
                                                        msg_callback=mock_msg_callback) is None
        assert len(mock_msg_callback.messages) == 2
        assert mock_msg_callback.messages[0] == "Config file is not properly formatted!"
        assert mock_msg_callback.messages[1] == "'compare_files' is a required property"
