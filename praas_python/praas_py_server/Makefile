# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
PYTHON_PATH ?= $(realpath $(shell sh -c "command -v python3"))

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

SGXAPP = sgx-praas-server

RA_TYPE ?= dcap
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0
XDG_CONFIG_HOME := $(shell echo $$XDG_CONFIG_HOME)
SGX_RSA_KEY_PATH ?= $(shell \
    if [ -z "$(XDG_CONFIG_HOME)" ]; then \
        echo "$(HOME)/.config/gramine/enclave-key.pem"; \
    else \
        echo "$(XDG_CONFIG_HOME)/gramine/enclave-key.pem"; \
    fi \
)

print_xdg_config_home:
	@echo $(XDG_CONFIG_HOME)

# The SGX server will spawn new gramine enclaves for ech request.
.PHONY: $(SGXAPP)
$(SGXAPP): print_xdg_config_home workdir envfile signkey
	$(PYTHON_PATH) $(SGXAPP).py

# It requires a .env with the params for dynamcillay creating 
# gramine manifests and .
SERVER_HOST ?= localhost
SERVER_PORT ?= 8888
IPC_PORT ?= 3491
WORK_DIR ?= /tmp/$(SGXAPP)
ENCLAVE_RA_TYPE ?= dcap
ENCLAVE_RA_CLIENT_SPID ?=
ENCLAVE_RA_CLIENT_LINKABLE ?= 0
ENV_FILE = .env 
GRAMINE_TEMPLATE = ./enclave/enclave.manifest.template
ifeq ($(DEBUG),1)
ENCLAVE_LOG_LEVEL = debug
else
ENCLAVE_LOG_LEVEL = error
endif

workdir:
	@if [ ! -d "$(WORK_DIR)" ]; then mkdir -p "$(WORK_DIR)"; fi

signkey:
	@if [ ! -f "$(SGX_RSA_KEY_PATH)" ]; then gramine-sgx-gen-private-key; fi

.PHONY: envfile
envfile:
	@echo "HOST=$(SERVER_HOST)" > $(ENV_FILE)
	@echo "PORT=$(SERVER_PORT)" >> $(ENV_FILE)
	@echo "IPC_PORT=$(IPC_PORT)" >> $(ENV_FILE)
	@echo "ARCH_LIBDIR=$(ARCH_LIBDIR)" >> $(ENV_FILE)
	@echo "PYTHON_PATH=$(PYTHON_PATH)" >> $(ENV_FILE)
	@echo "WORK_DIR=$(WORK_DIR)" >> $(ENV_FILE)
	@echo "GRAMINE_TEMPLATE=$(GRAMINE_TEMPLATE)" >> $(ENV_FILE)
	@echo "ENCLAVE_LOG_LEVEL=$(ENCLAVE_LOG_LEVEL)" >> $(ENV_FILE)
	@echo "ENCLAVE_RA_TYPE=$(ENCLAVE_RA_TYPE)" >> $(ENV_FILE)
	@echo "ENCLAVE_RA_CLIENT_SPID=$(ENCLAVE_RA_CLIENT_SPID)" >> $(ENV_FILE)
	@echo "ENCLAVE_RA_CLIENT_LINKABLE=$(ENCLAVE_RA_CLIENT_LINKABLE)" >> $(ENV_FILE)
	@echo "SGX_RSA_KEY_PATH=$(SGX_RSA_KEY_PATH)" >> $(ENV_FILE)

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig entrypoint
	$(RM) -rf $(WORK_DIR)/*
	$(RM) -r __pycache__
	$(RM) -r enclave/__pycache__
	$(RM) .env

.PHONY: distclean
distclean: clean