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
from enum import Enum
from pathlib import Path
import enum, pkg_resources, tempfile

import click, filehash, gnupg


# List of available verification modes, based on the command line options in the main CLI class
class VerificationModes(Enum):
    COMPARE_FILES = 'compare_files',
    VERIFY_VIA_CHECKSUM = 'verify_via_checksum',
    VERIFY_VIA_CHECKSUMFILE = 'verify_via_checksumfile',
    VERIFY_VIA_PGP = 'verify_via_pgp',
    VERIFY_VIA_PGPCHECKSUMFILE = 'verify_via_pgpchecksumfile'


# Location of the schema files
CANARY_INPUT_SCHEMA  = pkg_resources.resource_filename('icecrust', 'data/canary_input.schema.json')
CANARY_OUTPUT_SCHEMA = pkg_resources.resource_filename('icecrust', 'data/canary_output.schema.json')


class IcecrustCanaryUtils(object):
    """Various utility functions for the canary CLI"""
    @staticmethod
    def extract_verification_mode(config, msg_callback=None):
        """
        Extracts the correct verification mode from config file

        :param config: parsed JSON config
        :param msg_callback: message callback object, can be used to collect additional data via .echo()
        :return: one of VERIFICATION_MODES or None if none are found
        """
        for mode in VerificationModes:
            if str(mode.value[0]) in config:
                return mode

        return None
