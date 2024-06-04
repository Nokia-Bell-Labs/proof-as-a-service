# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import json
import os
import tarfile

from cryptography.hazmat.primitives import hashes

def extract_archive(filename, path):
    try:
        with tarfile.open(filename, "r:*") as tar:
            tar.extractall(path=path, members=tar)
    except tarfile.ExtractError as exc:
        raise


def compute_proof(data):
    enclave_output = {}
    hash = hashes.Hash(hashes.SHA256())
    if not isinstance(data, bytes):
        data = bytes(data, "utf-8")
    hash.update(data)
    enclave_output["input_hash"] = hash.finalize().hex()

    with open("/tmp/input_data.tar.gz", "wb") as f:
        f.write(data)
    
    filepath = "/tmp/input_data"
    extract_archive("/tmp/input_data.tar.gz", filepath)

    files = [f for f in os.listdir(filepath) if os.path.isfile(os.path.join(filepath, f))]

    filename = os.path.join(filepath, files[0])

    with open(filename, "r") as f:
        input_data = f.read()
    
    input_lines = input_data.split("\n")

    output = {}
    output["file_length"] = len(data)
    output["num_lines"] = len(input_lines)

    enclave_output["output"] = output

    return json.dumps(enclave_output, sort_keys=True)