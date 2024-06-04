#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

OUTPUT_DIR=$1
mkdir -p $OUTPUT_DIR
cd ..

for rate in 10000 20000 50000 100000 150000 200000
do
    echo "========================="
    for frequency in 1
    do
        echo "-----"
        #FNAME="dynamic_"$rate"_"$frequency".json"
        echo "BATCH_RATE=$rate, BATCH_FREQUENCY=$frequency"
        NUM_BATCHES=100 BATCH_RATE=$rate BATCH_FREQUENCY=$frequency python3 client.py localhost sampling_statistics dynamic dummy_name dummy_enclave
        sleep 1
    done
    mv received/*_summary.json eval/$OUTPUT_DIR/
    sleep 1
    echo "========================="
done

