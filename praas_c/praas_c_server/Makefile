# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

.PHONY: all server clean run enclaves clean_enclaves

# set OE_CRYPTO_LIB to either "mbedtls" or "openssl" based on the crypto wrapper to be used.
# OE_CRYPTO_LIB is case sensitive. Use all lowercase letters.
OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

AZDCAP_DEBUG_LOG_LEVEL := ""
export AZDCAP_DEBUG_LOG_LEVEL

all: server

enclaves:
	$(MAKE) -C enclaves

clean_enclaves:
	$(MAKE) -C enclaves clean

server:
	$(MAKE) -C server

clean:
	$(MAKE) -C server clean

run:
	server/praas_server
