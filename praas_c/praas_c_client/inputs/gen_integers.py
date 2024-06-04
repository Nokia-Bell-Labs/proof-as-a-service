# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import random
import sys

num_total = int(sys.argv[1])

data = []
for i in range(num_total):
    data.append(i*random.randint(4, 20))

for i in range(len(data)):
    print(data[i])