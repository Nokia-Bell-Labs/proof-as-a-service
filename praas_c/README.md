# PraaS for C/C++ enclaves

## Setup

1. Create an SGX-capable VM in Azure: Ubuntu 20.04 LTS, dc2s_v3

2. ssh into the VM

3. The following scripts configure dependencies and install openenclave.
They are copied from the original openenclave repo instructions (https://github.com/openenclave/openenclave/blob/v0.9.x/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md) and modified to match 20.04.

```
chmod +x install_vm_dependencies.sh
./install_vm_dependencies.sh
```

The SGX platform software is not needed, because the above VM comes with it installed.

4. edit .bashrc to add the environment variables to be enabled at login

```
. /opt/openenclave/share/openenclave/openenclaverc
```

## Running

1. Create the datasets to be tested by following the instructions in [praas_c_client/inputs/README.md](/praas_c/praas_c_client/inputs/README.md).

2. Then compile the enclaves and the server via:

```
cd praas_c_server/
make enclaves
make server
make run
cd ..
```

3. Then use the example scripts that will trigger various enclaves.
For more information, please check the comments in the scripts.

The client will also verify the proof (i.e., quote verification as well as the signature on the enclave output).

```
cd praas_c_client
./run_example_static.sh enclave_sampling inputs/hashes_1m.txt
./run_example_dynamic.sh enclave_statistics 20 10000
cd ..
```

4. For evaluation automation, please refer to the [praas_c_client/eval/README.md](/praas_c/praas_c_client/eval/README.md).