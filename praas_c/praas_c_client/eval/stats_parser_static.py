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


def compute_stats_static(stats_list):
    stats = {}
    for k in stats_list[0]:
        stats[k] = []
        
    for k in stats:
        for s in stats_list:
            stats[k].append(s[k])
    
    avgs = {}
    stdevs = {}
    for k in stats:
        avgs[k] = statistics.mean(stats[k])
        stdevs[k] = statistics.stdev(stats[k])
    
    return avgs, stdevs

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
    
    for fname in list_of_files:
        with open(fname, "r") as f:
            summary = json.load(f)
            data_filename = summary["data_filename"]
            input_size = data_filename[data_filename.rfind("_")+1:-4]
            if input_size not in stats_map:
                stats_map[input_size] = {}
                stats_map[input_size]["client_stats"] = []
                stats_map[input_size]["server_stats"] = []
            
            stats_map[input_size]["client_stats"].append(summary["client_stats"])
            stats_map[input_size]["server_stats"].append(summary["server_stats"])

    summary_stats = {}

    common_ops = ["01_elapsed_setup_remote_enclave", "02_elapsed_verify_quote"]
    stats_common = {}

    for input_size in stats_map:
        print(input_size)
        summary_stats[input_size] = {}
        
        client_avgs, client_stdevs = compute_stats_static(stats_map[input_size]["client_stats"])
        summary_client_stats = {}
        summary_client_stats["avgs"] = client_avgs
        summary_client_stats["stdevs"] = client_stdevs
        summary_stats[input_size]["client"] = summary_client_stats

        for common_op in common_ops:
            if common_op not in stats_common:
                stats_common[common_op] = {}
            stats_common[common_op][input_size] = summary_client_stats["avgs"][common_op]

        server_avgs, server_stdevs = compute_stats_static(stats_map[input_size]["server_stats"])
        summary_server_stats = {}
        summary_server_stats["avgs"] = server_avgs
        summary_server_stats["stdevs"] = server_stdevs
        summary_stats[input_size]["server"] = summary_server_stats

    print(stats_common)
    summary_stats["common_ops"] = {}
    for common_op in common_ops:
        summary_stats["common_ops"][common_op] = compute_stats(stats_common[common_op])

    #print(json.dumps(summary_stats, indent=4, sort_keys=True))
    with open("stats_summary_" + path + ".json", "w") as f:
        json.dump(summary_stats, f, indent=4, sort_keys=True)
    
    return summary_stats

if __name__ == '__main__':
    path = sys.argv[1]

    summary_stats = extract_stats_summary(path)
