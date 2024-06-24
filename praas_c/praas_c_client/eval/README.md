# PraaS C/C++ enclaves evaluation

This folder houses the scripts that were used to evaluate the system.

1. Make sure the server is running (explanations in [README.md](/praas_c/README.md)).

2. Make sure you created the static inputs for hashes (explanations in [../inputs/README.md](/praas_c/praas_c_client/inputs/README.md))

3. Use one of the `load` scripts to trigger runs. Give an output folder as the first argument to the script; the summary file for statistics for each run will be copied there.

For loading the server with static hash data (e.g., `hashes_[1,2,3,4,5]m.txt`) for `enclave_sampling`:

```
./load_static_sampling.sh eval_sampling
```

For loading the server with static hash data (e.g., `hashes_[1,2,3,4,5]m.txt`) for `enclave_nonrepetition_sampling`:

```
./load_static_nonrepetition_sampling.sh eval_nonrepetition_sampling
```

For loading the server with dynamic integer data (e.g., with rates ranging from 10K/sec to 200K/sec) for `enclave_statistics`:

```
./load_dynamic_statistics.sh eval_statistics
```

For loading the server with dynamic integer data (e.g., with rates ranging from 10K/sec to 200K/sec) for `enclave_sampling_statistics`:

```
./load_dynamic_sampling_statistics.sh eval_sampling_statistics
```

4. Use the appropriate `stats_parser` script to obtain the overall statistics of the runs in a given output folder (i.e., used when calling the above scripts).

For extracting the overall statistics from loading the server with static hash data for `enclave_sampling`:

```
python3 stats_parser_static.py eval_sampling
```

For extracting the overall statistics from loading the server with static hash data for `enclave_nonrepetition_sampling`:

```
python3 stats_parser_static.py eval_nonrepetition_sampling
```

For extracting the overall statistics from loading the server with dynamic integer data for `enclave_statistics`:

```
python3 stats_parser_dynamic.py eval_statistics
```

For extracting the overall statistics from loading the server with dynamic integer data for `enclave_sampling_statistics`:

```
python3 stats_parser_dynamic.py eval_sampling_statistics
```
