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
import json, re, shutil

import gnupg, jsonschema, pytest

from icecrust.canary_utils import VerificationModes, CANARY_INPUT_SCHEMA, CANARY_OUTPUT_SCHEMA

from test_utils import TEST_DIR, FILE1_HASH, FILE2_HASH


# Tests for misc utils methods
class TestUtils(object):
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
        assert True

    def test_input_schema_valid_file(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary/pnpm_input.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)
        assert True

    def test_input_schema_invalid_file(self):
        schema_data = json.load(open(CANARY_INPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary/pnpm_output.json', 'r'))
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                           format_checker=jsonschema.draft7_format_checker)

    def test_output_schema_valid_file(self):
        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary/pnpm_output.json', 'r'))
        jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                       format_checker=jsonschema.draft7_format_checker)
        assert True

    def test_output_schema_invalid_file(self):
        schema_data = json.load(open(CANARY_OUTPUT_SCHEMA, 'r'))
        parsed_data = json.load(open(TEST_DIR + 'canary/pnpm_input.json', 'r'))
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validators.validate(instance=parsed_data, schema=schema_data,
                                           format_checker=jsonschema.draft7_format_checker)


