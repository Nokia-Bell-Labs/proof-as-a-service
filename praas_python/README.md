# PraaS for Python enclaves

## Setup

1. Create an SGX-capable VM in Azure: Ubuntu 22.04 LTS, dc2s_v3.

	NOTE: The praas_server python runs also on Ubuntu 20.04. 
The default python in Ubuntu 20.04 is 3.8 compared with 3.10 in Ubuntu 22.04.
Bigger datasets may fail with an out-of-memory error in python3.8.
The proof for spamnet can be also generated in Ubuntu 20.04
(or if the other datasets are split into multiple pieces, they can also work).
Proofs for bigger datasets can be generated in Ubuntu 22.04 (cifar10, mnist, fashionmnist).

	If Ubuntu 20.04 is used, the requirements of the property computation functions
(e.g., `praas_py_client/property_computation_functions/mnist/requirements.txt`)
need to be adjusted to use python3.8 for torch (rather than 3.10).

2. ssh into the VM.

3. Run `install_vm_dependencies.sh` to configure dependencies and install openenclave. 
    This script is copied from the original openenclave repo instructions (https://github.com/openenclave/openenclave/blob/v0.9.x/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md) and modified to match 20.04.

	```bash
    chmod +x install_vm_dependencies.sh
    ./install_vm_dependencies.sh
	```

The SGX platform is not needed, because the above VM comes with SGX platform software installed.

## Running

1. Create the datasets:

	```bash
	cd praas_py_client/data
	python3 create_dataset_spamnet.py 1
	python3 create_dataset.py mnist 1
	python3 create_dataset.py fashionmnist 1
	python3 create_dataset.py cifar10 1
	cd ../..
	```

2. Run the server:

	```bash
	cd praas_py_server
	make sgx-praas-server
	```

3. Afterwards, you can trigger the proof generation via by running the client, which will also verify the proof (i.e., quote verification as well as verifying the enclave signature):

	```bash
	cd praas_py_client
	./run_example_proof.sh spamnet
	./run_example_proof.sh mnist
	./run_example_proof.sh fashionmnist
	./run_example_proof.sh cifar10
	```

	The produced proofs will be available under `proofs/` folder.

4. The produced proofs can also be verified standalone:

	```bash
	python3 check_proof.py proofs/proof_data_spamnet_data_0.tar.gz.json
	python3 check_proof.py proofs/proof_data_mnist_data_0.tar.gz.json
	python3 check_proof.py proofs/proof_data_fashionmnist_data_0.tar.gz.json
	python3 check_proof.py proofs/proof_data_cifar10_data_0.tar.gz.json
	```
