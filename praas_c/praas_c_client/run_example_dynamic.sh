#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

ENCLAVE_NAME=$1
NUM_BATCHES=$2
BATCH_RATE=$3

NUM_BATCHES=$NUM_BATCHES BATCH_RATE=$BATCH_RATE python3 client.py localhost $ENCLAVE_NAME dynamic dummy dummy
