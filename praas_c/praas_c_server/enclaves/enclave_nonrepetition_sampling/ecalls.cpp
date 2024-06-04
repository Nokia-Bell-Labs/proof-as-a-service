// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include <common/remoteattestation_t.h>
#include <openenclave/enclave.h>

#include "common/dispatcher.h"

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("Enclave1");
const char* enclave_name = "Enclave1";

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    TRACE_ENCLAVE("enter get_remote_report_with_pubkey");
    return dispatcher.get_remote_report_with_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

/*
int encrypt_secret_key_for_testing(message_t* message)
{
    return dispatcher.encrypt_secret_key_for_testing(message);
}
*/

int decrypt_and_set_secret_key(message_t* message)
{
    return dispatcher.decrypt_and_set_secret_key(message);
}

int decrypt_dataset_and_set_data(message_t* message)
{
    return dispatcher.decrypt_dataset_and_set_data(message);
}

int do_computation()
{
    return dispatcher.do_computation();
}

int get_signed_output(enclave_output_t* signed_output)
{
    return dispatcher.get_signed_output(signed_output);
}

