// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "attestation.h"
#include "crypto.h"
#include <../enclave_sampling/prover.h>

using namespace std;

class ecall_dispatcher
{
  private:
    bool m_initialized;
    Crypto* m_crypto;
    Attestation* m_attestation;
    Prover* m_prover;
    string m_name;

    // Proof-of-Property variables
    uint8_t* input_data;
    size_t size_input_data;

    uint8_t* secret_key;
    size_t size_secret_key;
    
    uint8_t* output_data;
    size_t size_output_data;

    uint8_t hash_input_data[32];
    uint8_t hash_output_data[32];
    uint8_t signature[256];

  public:
    ecall_dispatcher(const char* name);
    ~ecall_dispatcher();
    
    int get_remote_report_with_pubkey(
        uint8_t** pem_key,
        size_t* key_size,
        uint8_t** remote_report,
        size_t* remote_report_size);

    // shouldn't actually be here
    //int encrypt_secret_key_for_testing(message_t* message);

    int decrypt_and_set_secret_key(message_t* message);

    int decrypt_dataset_and_set_data(message_t* encrypted_dataset);

    // will delagate to user-provided function
    int do_computation();

    int get_signed_output(enclave_output_t* signed_output);

  private:
    bool initialize(const char* name);
    void printHex(const char* name, uint8_t* buffer, int size);
};
