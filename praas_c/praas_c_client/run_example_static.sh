#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# one of "sampling", "nonrepetition_sampling", "statistics", "sampling_statistics"
ENCLAVE_NAME=$1

# input filename
# for "sampling" and "nonrepetition_sampling", file with hash strings encoded in hex
# for "statistics" and "sampling_statistics", file with one integer per line
INPUT_FILENAME=$2

python3 client.py localhost $ENCLAVE_NAME static $INPUT_FILENAME dummy
