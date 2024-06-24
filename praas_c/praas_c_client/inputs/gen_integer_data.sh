#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

python3 gen_integers.py 10000 > integers_10k.txt

python3 gen_integers.py 100000 > integers_100k.txt
