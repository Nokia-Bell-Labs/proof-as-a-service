#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

OUTPUT_DIR=$1
mkdir -p $OUTPUT_DIR
cd ..

for SIZE in 1m 2m 3m 4m 5m
do
    echo "========================="
    echo $SIZE
    echo "-----"
    for i in {1..20}
    do
        python3 client.py localhost nonrepetition_sampling static inputs/hashes_$SIZE.txt dummy
        sleep 1
        echo "$i-----"
    done
    mv received/*_summary.json eval/$OUTPUT_DIR/
    sleep 1
    echo "========================="
done
