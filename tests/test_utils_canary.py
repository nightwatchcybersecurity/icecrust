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
import json, os

import jsonschema, pytest

from icetrust.utils_canary import\
    VerificationModes, CANARY_INPUT_SCHEMA, CANARY_OUTPUT_SCHEMA, DEFAULT_HASH_ALGORITHM
from icetrust.utils_canary import IcetrustCanaryUtils

from test_utils import mock_msg_callback, TEST_DIR


# Tests for misc utils methods
class TestCanaryUtils(object):
    def test_const_verification_modes(self):
        assert len(VerificationModes) == 5
        assert VerificationModes['COMPARE_FILES'] is not None
        assert VerificationModes['CHECKSUM'] is not None
        assert VerificationModes['CHECKSUMFILE'] is not None
        assert VerificationModes['PGP'] is not None
        assert VerificationModes['PGPCHECKSUMFILE'] is not None

    def test_canary_schemas_valid(self):
        input_schema = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        output_schema = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        jsonschema.Draft7Validator.check_schema(input_schema)
        jsonschema.Draft7Validator.check_schema(output_schema)

    def test_input_schema_valid_compare(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'compare.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_checksum(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'checksum.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_checksumfile(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'checksumfile.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_pgp_keyfile(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'pgp_keyfile.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_pgp_keyid(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'pgp_keyid.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_pgpchecksumfile_keyid(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'pgpchecksumfile_keyid.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_valid_pgpchecksumfile_keyfile(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'pgpchecksumfile_keyfile.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_input_schema_invalid_file(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = \
            json.load(open(os.path.join(TEST_DIR, 'canary_output', 'compare.json'), 'r'))
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                           format_checker=jsonschema.draft7_format_checker)

    def test_output_schema_valid_file(self):
        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        parsed_data = \
            json.load(open(os.path.join(TEST_DIR, 'canary_output', 'compare.json'), 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

    def test_output_schema_invalid_file(self):
        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(os.path.join(TEST_DIR, 'canary_input', 'compare.json'), 'r'))
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                           format_checker=jsonschema.draft7_format_checker)


# Tests for extract_verification_data method
class TestExtractVerificationData(object):
    def test_valid(self):
        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'compare.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES) is not None

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'checksum.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.CHECKSUM) is not None

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'checksumfile.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.CHECKSUMFILE)\
               is not None

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgp_keyfile.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.PGP) is not None

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgp_keyid.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.PGP) is not None

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgpchecksumfile_keyfile.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.PGPCHECKSUMFILE)\
               is not None

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgpchecksumfile_keyid.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.PGPCHECKSUMFILE)\
               is not None

    def test_valid_verbose(self, mock_msg_callback):
        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'compare.json')), 'r'))
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES,
                                                             msg_callback=mock_msg_callback) is not None
        assert len(mock_msg_callback.messages) == 1
        assert mock_msg_callback.messages[0] ==\
               "Verification data: {'file2_url': 'https://files.pythonhosted.org/packages/c8/6f/730a38dc98dd4a9dad644515700c29050c4672594def4d7f6f2f1bda28ae/truegaze-0.1.7-py3-none-any.whl'}"

    def test_invalid(self):
        config = dict()
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES) is None

    def test_invalid_verbose(self, mock_msg_callback):
        config = dict()
        assert IcetrustCanaryUtils.extract_verification_data(config, VerificationModes.COMPARE_FILES,
                                                             msg_callback=mock_msg_callback) is None
        assert len(mock_msg_callback.messages) == 0


# Tests for generate_json method
class TestGenerateJson(object):
    def test_valid(self, tmp_path):
        config_data = dict()
        config_data['name'] = 'foobar1'
        config_data['url'] = 'https://www.example.com'
        config_data['filename_url'] = 'https://www.example.com/file.sh'
        verification_mode = VerificationModes.PGPCHECKSUMFILE
        verified_result = False
        cmd_output = ['foobar2', 'foobar3']
        json_raw = IcetrustCanaryUtils.generate_json(config_data, verification_mode, verified_result, cmd_output,
                                                     os.path.join(TEST_DIR, 'file1.txt'))
        json_parsed = json.loads(json_raw)

        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        jsonschema.validators.validate(instance=json_parsed, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)

        assert(json_parsed['name']) == config_data['name']
        assert(json_parsed['url']) == config_data['url']
        assert(json_parsed['filename_url']) == config_data['filename_url']
        assert(json_parsed['verification_mode']) == VerificationModes.PGPCHECKSUMFILE.value
        assert (json_parsed['verified']) == verified_result
        assert (json_parsed['output']) == ', '.join(cmd_output)


# Tests for get_verification_mode method
class TestGetVerificationMode(object):
    def test_valid(self):
        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'compare.json')), 'r'))
        assert IcetrustCanaryUtils.get_verification_mode(config) == VerificationModes.COMPARE_FILES

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'checksum.json')), 'r'))
        assert IcetrustCanaryUtils.get_verification_mode(config) == VerificationModes.CHECKSUM

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'checksumfile.json')), 'r'))
        assert IcetrustCanaryUtils.get_verification_mode(config) == VerificationModes.CHECKSUMFILE

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgp_keyfile.json')), 'r'))
        assert IcetrustCanaryUtils.get_verification_mode(config) == VerificationModes.PGP

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgp_keyid.json')), 'r'))
        assert IcetrustCanaryUtils.get_verification_mode(config) == VerificationModes.PGP

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgpchecksumfile_keyfile.json')), 'r'))
        assert IcetrustCanaryUtils.get_verification_mode(config) == VerificationModes.PGPCHECKSUMFILE

        config = IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgpchecksumfile_keyid.json')), 'r'))
        assert IcetrustCanaryUtils.get_verification_mode(config) == VerificationModes.PGPCHECKSUMFILE

    def test_invalid(self):
        config = dict()
        assert IcetrustCanaryUtils.get_verification_mode(config) is None


# Tests for get_algorithm method
class TestGetAlgorithm(object):
    def test_valid(self):
        verification_data = dict()
        verification_data['algorithm'] = 'sha1'
        assert IcetrustCanaryUtils.get_algorithm(verification_data) == 'sha1'

    def test_valid_default(self):
        verification_data = dict()
        assert IcetrustCanaryUtils.get_algorithm(verification_data) == DEFAULT_HASH_ALGORITHM

    def test_valid_verbose(self, mock_msg_callback):
        verification_data = dict()
        verification_data['algorithm'] = 'sha1'
        assert IcetrustCanaryUtils.get_algorithm(verification_data, msg_callback=mock_msg_callback) == 'sha1'
        assert len(mock_msg_callback.messages) == 1
        assert mock_msg_callback.messages[0] == "Using algorithm: sha1"

    def test_valid_default_verbose(self, mock_msg_callback):
        verification_data = dict()
        assert IcetrustCanaryUtils.get_algorithm(verification_data, msg_callback=mock_msg_callback)\
               == DEFAULT_HASH_ALGORITHM
        assert len(mock_msg_callback.messages) == 1
        assert mock_msg_callback.messages[0] == "Using algorithm: sha256"


# Tests for validate_config_file method
class TestValidateConfigFile(object):
    def test_valid(self):
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'compare.json')), 'r')) is not None
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'checksum.json')), 'r')) is not None
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'checksumfile.json')), 'r')) is not None
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgp_keyfile.json')), 'r')) is not None
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgp_keyid.json')), 'r')) is not None
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgpchecksumfile_keyfile.json')), 'r')) is not None
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'pgpchecksumfile_keyid.json')), 'r')) is not None

    def test_valid_verbose(self, mock_msg_callback):
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_input', 'compare.json')), 'r'),
            msg_callback=mock_msg_callback) is not None
        assert len(mock_msg_callback.messages) == 0

    def test_invalid(self):
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_output', 'compare.json')), 'r')) is None

    def test_invalid_verbose(self, mock_msg_callback):
        assert IcetrustCanaryUtils.validate_config_file(
            open(os.path.join(TEST_DIR, os.path.join('canary_output', 'compare.json')), 'r'),
            msg_callback=mock_msg_callback) is None
        assert len(mock_msg_callback.messages) == 2
        assert mock_msg_callback.messages[0] == "Config file is not properly formatted!"
        assert mock_msg_callback.messages[1] == "'compare_files' is a required property"
