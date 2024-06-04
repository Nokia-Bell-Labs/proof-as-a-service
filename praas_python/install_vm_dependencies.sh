# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# add SGX repo
sudo curl -fsSLo /usr/share/keyrings/intel-sgx-deb.asc https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" | sudo tee /etc/apt/sources
.list.d/intel-sgx.list

# add gramine repo
sudo curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/gramine.list

### Install dcap and gramine
sudo apt update
sudo apt install -y libsgx-dcap-ql gramine

# install python packages
sudo apt install -y python3-pip
sudo pip3 install cmake azure-security-attestation azure-identity flask python-dotenv cryptography requests cffi
