#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

python3 gen_hashes.py 5000000

head -1000000 hashes_5m.txt > hashes_1m.txt

head -2000000 hashes_5m.txt > hashes_2m.txt

head -3000000 hashes_5m.txt > hashes_3m.txt

head -4000000 hashes_5m.txt > hashes_4m.txt
