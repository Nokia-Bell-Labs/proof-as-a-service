# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

num_total = int(sys.argv[1])

def get_hashes(num_total):
    if num_total % 1000000 == 0:
        name = str(int(num_total / 1000000)) + "m"
    elif num_total % 1000 == 0:
        name = str(int(num_total / 1000)) + "k"
    else:
        name = str(num_total)

    with open("hashes_" + name + ".txt", "w") as f:
        for i in range(num_total):
            h = hashes.Hash(hashes.SHA256(), backend=default_backend())
            h.update(bytearray(i))
            h = h.finalize().hex()

            f.write(h + "\n")

get_hashes(num_total)
