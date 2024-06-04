#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

DATASET_NAME=$1

python3 proof_client.py "http://localhost:8888/sgx" "python" "./property_computation_functions/$DATASET_NAME" "pcf_$DATASET_NAME" "compute_proof" "data/$DATASET_NAME/data_0.tar.gz"