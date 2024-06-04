# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

.PHONY: all clean

# set OE_CRYPTO_LIB to either "mbedtls" or "openssl" based on the crypto wrapper to be used.
# OE_CRYPTO_LIB is case sensitive. Use all lowercase letters.
OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

AZDCAP_DEBUG_LOG_LEVEL := ""
export AZDCAP_DEBUG_LOG_LEVEL

all: build

reproduce:
	$(MAKE) -C enclave_sampling reproduce
	$(MAKE) -C enclave_statistics reproduce
	$(MAKE) -C enclave_sampling_statistics reproduce
	$(MAKE) -C enclave_nonrepetition_sampling reproduce

enc_stats:
	$(MAKE) -C enclave_statistics

enc_sampling:
	$(MAKE) -C enclave_sampling

enc_sampling_statistics:
	$(MAKE) -C enclave_sampling_statistics

enc_nonrepetition_sampling:
	$(MAKE) -C enclave_nonrepetition_sampling

build:
	$(MAKE) -C enclave_sampling
	$(MAKE) -C enclave_statistics
	$(MAKE) -C enclave_sampling_statistics
	$(MAKE) -C enclave_nonrepetition_sampling

clean:
	$(MAKE) -C enclave_sampling clean
	$(MAKE) -C enclave_statistics clean
	$(MAKE) -C enclave_sampling_statistics clean
	$(MAKE) -C enclave_nonrepetition_sampling clean
