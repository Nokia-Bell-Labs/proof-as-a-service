# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os
from pathlib import Path
import sys
import tarfile

ASSETS_DIR = 'spamnet/'
NUM_DATASETS = int(sys.argv[1])

TRAIN_DATASET_RATIO = float(os.getenv("TRAIN_DATASET_RATIO", 0.85))
TEST_DATASET_RATIO = 1 - TRAIN_DATASET_RATIO

if not os.path.exists(ASSETS_DIR):
    os.mkdir(ASSETS_DIR)

file_path = Path(__file__).parent.absolute()
f = open(os.path.join(file_path, 'spam.csv'), 'r', encoding='latin-1')
lines = f.read()
lines = lines.split("\n")
f.close()
#skip header
header = lines[0]
del lines[0]

#random.shuffle(lines)

train_dataset_size = int(len(lines) * TRAIN_DATASET_RATIO)

# split the dataset into training + test
# split the training part into individual owners
dataset_size_per_worker = int(train_dataset_size / NUM_DATASETS)
print("total dataset size: {}, training ratio: {}".format(len(lines), TRAIN_DATASET_RATIO))
print("dataset size per worker: {}".format(dataset_size_per_worker))
for worker_id in range(NUM_DATASETS):
    start = worker_id * dataset_size_per_worker
    end = start + dataset_size_per_worker
    print(start, end)
    f = open(ASSETS_DIR + "data_" + str(worker_id) + ".csv", "w")
    f.write(header + "\n")
    for i in range(start, end):
        f.write(lines[i] + "\n")

    f.close()

    #  archive the file
    with tarfile.open(ASSETS_DIR + "data_" + str(worker_id) + ".tar.gz", "w:gz") as tar:
        tar.add(ASSETS_DIR + "data_" + str(worker_id) + ".csv", "data_" + str(worker_id) + ".csv")

start = NUM_DATASETS * dataset_size_per_worker
end = len(lines)
f = open(ASSETS_DIR + "data_test.csv", "w")
f.write(header + "\n")
for i in range(start, end):
    f.write(lines[i] + "\n")

f.close()

# archive the file
with tarfile.open(ASSETS_DIR + "data_test.tar.gz", "w:gz") as tar:
    tar.add(ASSETS_DIR + "data_test.csv", "data_test.csv")
