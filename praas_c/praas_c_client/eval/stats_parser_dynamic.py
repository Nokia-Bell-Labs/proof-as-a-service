# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import json
import os
import statistics
import sys

def get_keys(filename):
    keys = []
    f = open(filename, "r")
    stats = json.load(f)

    keys = stats.keys()

    return keys, stats["requested_computation"]


def compute_stats(latencies):
    avg = statistics.mean(latencies.values())
    stdev = statistics.stdev(latencies.values())
    
    return avg, stdev

def extract_stats_summary(path):
    print(path)
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for fname in files:
            list_of_files.append(os.path.join(root,fname))

    keys, requested_computation = get_keys(list_of_files[0])
    print(keys, requested_computation)
    stats_map = {}
    
    common_ops = ["01_elapsed_setup_remote_enclave", "02_elapsed_verify_quote"]
    stats_common = {}
    
    for fname in list_of_files:
        with open(fname, "r") as f:
            summary = json.load(f)
            batch_size = summary["batch_size"]
            stats_map[batch_size] = {}
            stats_map[batch_size]["client_stats"] = summary["client_stats"]
            for common_op in common_ops:
                if common_op not in stats_common:
                    stats_common[common_op] = {}
                stats_common[common_op][batch_size] = summary["client_stats"][common_op]

    summary_stats = {}
    for batch_size in stats_map:
        print(batch_size)
        summary_stats[batch_size] = {}
        
        avg, stdev = compute_stats(stats_map[batch_size]["client_stats"]["80_dynamic_elapsed"])
        summary_client_stats = {}
        summary_client_stats["avg"] = avg
        summary_client_stats["stdev"] = stdev
        summary_stats[batch_size]["client"] = summary_client_stats
    
    print(stats_common)
    summary_stats[0] = {}
    for common_op in common_ops:
        summary_stats[0][common_op] = compute_stats(stats_common[common_op])
    
    print(json.dumps(summary_stats, indent=4, sort_keys=True))
    with open("stats_summary_" + path + ".json", "w") as f:
        json.dump(summary_stats, f, indent=4, sort_keys=True)
    
    return summary_stats

if __name__ == '__main__':
    path = sys.argv[1]

    summary_stats = extract_stats_summary(path)
