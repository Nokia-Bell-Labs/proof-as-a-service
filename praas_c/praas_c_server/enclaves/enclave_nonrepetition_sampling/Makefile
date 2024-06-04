# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
CRYPTO_LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

OE_CRYPTO_LIB := mbedtls
export OE_CRYPTO_LIB

AZDCAP_DEBUG_LOG_LEVEL := ""
export AZDCAP_DEBUG_LOG_LEVEL

all:
	$(MAKE) genkey
	$(MAKE) build
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

genkey: public.pem

private2.pem:
	openssl genrsa -out $@ -3 3072

public2.pem: private2.pem
	openssl rsa -in $< -out $@ -pubout

reproduce: public2.pem
	cp enclave_nonrepetition_sampling.signed enclave_nonrepetition_sampling.original.signed
	oesign sign -e enclave_nonrepetition_sampling -c enc.conf -k private2.pem
	cp enclave_nonrepetition_sampling.signed enclave_nonrepetition_sampling.reproduction.signed
	cp enclave_nonrepetition_sampling.original.signed enclave_nonrepetition_sampling.signed
	oesign dump -e enclave_nonrepetition_sampling.original.signed | grep -v "mrsigner" | grep -v "signature" > dump.original.out
	oesign dump -e enclave_nonrepetition_sampling.reproduction.signed | grep -v "mrsigner" | grep -v "signature" > dump.reproduction.out
	diff -s dump.original.out dump.reproduction.out

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../../remoteattestation.edl --trusted --trusted-dir ../common \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I../../../include -I. -I.. -std=c++11 -DOE_API_VERSION=2 ecalls.cpp prover.cpp ../common/dispatcher.cpp ../common/attestation.cpp ../common/crypto.cpp 
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/remoteattestation_t.c
	$(CXX) -o enclave_nonrepetition_sampling prover.o attestation.o crypto.o ecalls.o dispatcher.o remoteattestation_t.o $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e enclave_nonrepetition_sampling -c enc.conf -k private.pem

clean:
	rm -f *.o enclave_nonrepetition_sampling *.signed ../common/remoteattestation_t.* ../common/remoteattestation_args.h *.out
