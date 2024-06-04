# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

from .enclave import Enclave
from .dispatcher import DispatcherFactory, API_TO_ECALL_MAP

START_SCRIPT = 'start.py'

MODULE_FILES = {
    '__init__.py',
    'start.py',
    'enclave.py',
    'dispatcher.py'
}