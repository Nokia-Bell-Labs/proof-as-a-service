// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include "dispatcher.h"
#include <openenclave/enclave.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name)
    : m_crypto(NULL), m_attestation(NULL), m_prover(NULL)
{
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;

    if (m_prover)
        delete m_prover;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        goto exit;
    }

    m_attestation = new Attestation(m_crypto);
    if (m_attestation == NULL)
    {
        goto exit;
    }

    m_prover = new Prover();
    if (m_prover == NULL)
    {
        goto exit;
    }

    ret = true;

exit:
    return ret;
}

void ecall_dispatcher::printHex(const char* name, uint8_t* buffer, int size)
{
    const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    int len_name = strlen(name);
    char* buf = (char*) malloc(size*2 + len_name + 4 + 1);
    memcpy(buf, name, len_name);
    memcpy(buf+len_name, ": 0x", 4);
    for (int i = 0; i < size; i++)
    {
        char hex[2];
        hex[0] = hexmap[(buffer[i] & 0xF0) >> 4];
        hex[1] = hexmap[buffer[i] & 0x0F];
        memcpy(buf+len_name+4+i*2, hex, 2);
    }
    buf[len_name+4+size*2] = '\0';
    TRACE_ENCLAVE("%s", buf);
    free(buf);
}

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * The enclave that receives the key will use the remote report to attest this
 * enclave.
 */
int ecall_dispatcher::get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    uint8_t pem_public_key[512];
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* key_buf = NULL;
    int ret = 1;

    TRACE_ENCLAVE("get_remote_report_with_pubkey");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a remote report for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_remote_report(
            pem_public_key, sizeof(pem_public_key), &report, &report_size))
    {
        // Allocate memory on the host and copy the report over.
        *remote_report = (uint8_t*)oe_host_malloc(report_size);
        if (*remote_report == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*remote_report, report, report_size);
        *remote_report_size = report_size;
        oe_free_report(report);

        key_buf = (uint8_t*)oe_host_malloc(512);
        if (key_buf == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_buf, pem_public_key, sizeof(pem_public_key));

        *pem_key = key_buf;
        *key_size = sizeof(pem_public_key);

        ret = 0;
        TRACE_ENCLAVE("get_remote_report_with_pubkey succeeded");
    }
    else
    {
        TRACE_ENCLAVE("get_remote_report_with_pubkey failed.");
    }

exit:
    if (ret != 0)
    {
        if (report)
            oe_free_report(report);
        if (key_buf)
            oe_host_free(key_buf);
        if (*remote_report)
            oe_host_free(*remote_report);
    }
    return ret;
}

int ecall_dispatcher::decrypt_and_set_secret_key(message_t* message)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    data_size = sizeof(data);
    if (m_crypto->decrypt(message->data, message->size, data, &data_size))
    {
        size_secret_key = data_size;
        secret_key = (uint8_t*)malloc(size_secret_key);
        memcpy(secret_key, data, size_secret_key);
        //printHex("Decrypted data", data, data_size);
    }
    else
    {
        TRACE_ENCLAVE("Enclave:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    ret = 0;
exit:
    return ret;

}

int ecall_dispatcher::decrypt_dataset_and_set_data(message_t* encrypted_dataset)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    size_input_data = encrypted_dataset->size;
    input_data = (uint8_t*) malloc (size_input_data);
    if (input_data == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("out of memory");
        goto exit;
    }

    TRACE_ENCLAVE("size encrypted dataset: %ld", encrypted_dataset->size);
    // encrypted_dataset should be decrypted using the secret_key of the enclave, 
    // which would be received from the client
    // TODO: do this decryption at a block level?
    for (int i = 0; i < encrypted_dataset->size; i++)
    {
        uint8_t pd = encrypted_dataset->data[i] ^ secret_key[i%size_secret_key];
        //TRACE_ENCLAVE("%d XOR %d = %d\n", encrypted_dataset->data[i], secret_key[i%size_secret_key], pd);
        //TRACE_ENCLAVE("%c", pd);
        memcpy(input_data+i, &pd, sizeof(uint8_t));
    }
    
    //printHex("input_data", input_data, size_input_data);
    
    // 1. generate the input data hash
    if (m_crypto->Sha256(input_data, size_input_data, hash_input_data) == 0)
    {
        TRACE_ENCLAVE("Generated hash of input data");
        printHex("hash_input_data", hash_input_data, 32);
    }
    else
    {
        TRACE_ENCLAVE("Enclave:ecall_dispatcher::generate_input_data_hash failed");
        goto exit;
    }

    ret = 0;
exit:
    return ret;
}

// delegate to user-provided function
int ecall_dispatcher::do_computation()
{
    int ret = 1;
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    ret = m_prover->do_computation(input_data, size_input_data, &output_data, &size_output_data);
    if (ret != 0)
    {
        goto exit;
    }

    if (input_data)
    {
        free(input_data);
    }

    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::get_signed_output(enclave_output_t* signed_output)
{
    int ret = 1;

    uint8_t signature_input[96];
    uint8_t hash_signature_input[32];

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    // 3. generate output hash
    if (m_crypto->Sha256(output_data, size_output_data, hash_output_data) == 0)
    {
        TRACE_ENCLAVE("Generated hash of output data");
        printHex("hash_output_data", hash_output_data, 32);
    }
    else
    {
        TRACE_ENCLAVE("Enclave:ecall_dispatcher::generate_output_data_hash failed");
        goto exit;
    }

    signed_output->size_output_data = size_output_data;
    signed_output->output_data = (uint8_t*) malloc (size_output_data);
    if (signed_output->output_data == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying host_buffer failed, out of memory");
        goto exit;
    }
    // TODO: should or not encrypt?
    // if this is part of the public proof, then there is no point.
    // encrypt output with the key shared with the client
    /*
    for (int i = 0; i < size_output_data; i++)
    {
        uint8_t ed = output_data[i] ^ secret_key[i%size_secret_key];
        //TRACE_ENCLAVE("%d XOR %d = %d\n", output_data[i], secret_key[i%size_secret_key], ed);
        //TRACE_ENCLAVE("%c", ed);
        memcpy(signed_output->output_data+i, &ed, sizeof(uint8_t));
    }
    */
    memcpy(signed_output->output_data, output_data, size_output_data);

    if (output_data)
    {
        free(output_data);
    }

    // 4. sign hash_input and hash_output
    memcpy(signature_input, hash_input_data, 32);
    memcpy(signature_input+32, hash_output_data, 32);
    if (m_crypto->Sha256(signature_input, 64, hash_signature_input) == 0)
    {
        TRACE_ENCLAVE("Generated hash of signature input (hash_input||hash_output)");
        printHex("hash_signature_input", hash_signature_input, 32);
    }
    else
    {
        TRACE_ENCLAVE("Enclave:ecall_dispatcher::generate_signature_input_hash failed");
        goto exit;
    }

    // sign the hash_signature_input
    if (m_crypto->Sign(hash_signature_input, signature))
    {
        TRACE_ENCLAVE("Generated signature of output data");
        printHex("signature", signature, 256);
    }
    else
    {
        TRACE_ENCLAVE("Enclave:ecall_dispatcher::generate_signature failed");
        goto exit;
    }

    TRACE_ENCLAVE("Generated and signed the output data");

    // copy hash_input_data, hash_output_data, output_data, size_output_data and signature to signed_output
    
    signed_output->hash_input_data = (uint8_t*) malloc (32);
    memcpy(signed_output->hash_input_data, hash_input_data, 32);
    signed_output->hash_output_data = (uint8_t*) malloc (32);
    memcpy(signed_output->hash_output_data, hash_output_data, 32);
    signed_output->signature = (uint8_t*) malloc (256);
    memcpy(signed_output->signature, signature, 256);
    
    ret = 0;

exit:
    return ret;

}
