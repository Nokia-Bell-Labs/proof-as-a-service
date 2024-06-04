// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include <openenclave/host.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <uuid/uuid.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "json.hpp"

#include "remoteattestation_u.h"

#include "print_utils.h"
#include "net_utils.h"
#include "socket_utils.h"

#define ENCLAVE_SAMPLING_PATH "./enclaves/enclave_sampling/enclave_sampling.signed"
#define ENCLAVE_STATISTICS_PATH "./enclaves/enclave_statistics/enclave_statistics.signed"
#define ENCLAVE_SAMPLING_STATISTICS_PATH "./enclaves/enclave_sampling_statistics/enclave_sampling_statistics.signed"
#define ENCLAVE_NONREPETITION_SAMPLING_PATH "./enclaves/enclave_nonrepetition_sampling/enclave_nonrepetition_sampling.signed"

// "stats_" + <uuid> + ".txt" + '\0'
//#define STATS_FILENAME_LEN 47

//#define STATS_DIR "./stats"

using json = nlohmann::json;
using namespace std;

typedef struct times_s
{
    json items;
} timings;

uint8_t* convertHexToBytes(const char* hex_buffer, int size)
{
    int size_buffer = size / 2;
    uint8_t* buffer = (uint8_t*) malloc (size_buffer * sizeof(uint8_t));
    for (int i = 0; i < size; i+=2)
    {
        char buf[2];
        buf[0] = hex_buffer[i];
        buf[1] = hex_buffer[i+1];
        uint8_t val = strtol(buf, NULL, 16);
        //printf("%c %c = %d\n", buf[0], buf[1], val);
        buffer[i/2] = val;
    }
    return buffer;
}

char* convertBytesToHex(const uint8_t* buffer, size_t size)
{
    char* hex = (char*) malloc(sizeof(char) * (size*2+1));
    for (int i = 0; i < size; i++)
    {
        sprintf(&hex[i*2], "%02x", buffer[i]);
    }
    hex[size*2] = '\0';
    return hex;
}

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;
    uint32_t flags = 0;

    if (strstr(enclave_path, "debug") != NULL)
    {
        flags = OE_ENCLAVE_FLAG_DEBUG;
    }

    printf("Server: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_remoteattestation_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        flags,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Server: oe_create_remoteattestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Server: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Server: Enclave successfully terminated.\n");
}

int create_enclave_and_get_quote(const char* enclave_path, oe_enclave_t** enclave, oe_report_t* parsed_report, uint8_t** pem_key, size_t* pem_key_size, uint8_t** remote_report, size_t* remote_report_size, timings* time_map)
{
    struct timeval t0;
    struct timeval t1;
    long long elapsed_create_enclave, elapsed_report_pubkey, elapsed_parse_report, elapsed_quote;

    oe_result_t result = OE_OK;

    int ret = 1;

    myprintf("Server: Creating the enclave\n");
    gettimeofday(&t0, 0);
    *enclave = create_enclave(enclave_path);
    gettimeofday(&t1, 0);
    elapsed_create_enclave = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;
    printf("Server: create enclave (microseconds): %lld\n", elapsed_create_enclave);
    time_map->items["02_elapsed_create_enclave"] = elapsed_create_enclave;
    if (enclave == NULL)
    {
        goto exit;
    }

    printf("Server: Requesting a remote report and the encryption key from the enclave\n");
    gettimeofday(&t0, 0);
    result = get_remote_report_with_pubkey(
        *enclave,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    gettimeofday(&t1, 0);

    if ((result != OE_OK) || (ret != 0))
    {
        printf("Server: get_remote_report_with_pubkey failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    elapsed_report_pubkey = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;
    printf("Server: remote report with pubkey (microseconds): %lld\n", elapsed_report_pubkey);
    time_map->items["03_elapsed_get_report_pubkey"] = elapsed_report_pubkey;

    //printf("Server: The enclave's public key: \n%s\n", *pem_key);

    printf("Server: Parsing the generated report\n");
    result = oe_parse_report(*remote_report, *remote_report_size, parsed_report);
    if (result != OE_OK)
    {
        printf(
            "Server: oe_parse_report failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    ret = 0;
exit:
    if (ret == 1)
    {
        if (*pem_key)
            free(*pem_key);

        if (*remote_report)
            free(*remote_report);
    }
    return ret;
}

int handle_one_batch_data(int client_socket, oe_enclave_t** enclave, uint8_t** pem_key, size_t* pem_key_size, bool* should_stop, timings* time_map)
{
    message_t encrypted_message = {0};
    enclave_output_t signed_output;
    json output_json;
    std::string output_json_str;

    int ret = 1;
    oe_result_t result = OE_OK;

    struct timeval t0;
    struct timeval t1;
    long long elapsed_computation_result, elapsed_signature, elapsed_output_json;

    char* output_str;

    uint8_t* encrypted_session_key_bytes;
    uint8_t* encrypted_data_bytes;

    gettimeofday(&t0, 0);
    char* buf2 = receive_data(client_socket);
    gettimeofday(&t1, 0);
    time_map->items["05_elapsed_receive_encrypted_data"] = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;

    //printf("Received: %s, %ld\n", buf2, strlen(buf2));

    gettimeofday(&t0, 0);
    auto jdata = json::parse(buf2);
    free(buf2);
    std::string encrypted_session_key_hex = json::parse(to_string(jdata["EncryptedSessionKey"]));
    std::string encrypted_data_hex = json::parse(to_string(jdata["EncryptedData"]));
    auto stop = jdata["ShouldStop"].get<bool>();
    //printf("%d\n", stop);
    if (stop)
    {
        *should_stop = true;
        send_data(client_socket, "");
        ret = 0;
        goto exit;
    }
    //printf("%s, %d\n", encrypted_session_key_hex.c_str(), strlen(encrypted_session_key_hex.c_str()));

    // 7. decrypt the session key in the enclave
    printf("Server: Sending encrypted secret key to the enclave...\n");
    encrypted_session_key_bytes = convertHexToBytes(encrypted_session_key_hex.c_str(), strlen(encrypted_session_key_hex.c_str()));
    //printHex(encrypted_session_key_bytes, strlen(encrypted_session_key_hex.c_str())/2, "Encrypted session key bytes: ");
    encrypted_message.data = encrypted_session_key_bytes;
    encrypted_message.size = strlen(encrypted_session_key_hex.c_str())/2;

    result = decrypt_and_set_secret_key(*enclave, &ret, &encrypted_message);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Server: decrypt_and_set_secret_key failed. %s\n", oe_result_str(result));
        exit(0);
    }
    
    if (encrypted_message.data)
    {
        free(encrypted_message.data);
    }

    // 8. decrypt the input data in the enclave
    encrypted_data_bytes = convertHexToBytes(encrypted_data_hex.c_str(), strlen(encrypted_data_hex.c_str()));
    //printHex(encrypted_data_hex, strlen(encrypted_data_hex.c_str())/2, "Encrypted session key bytes: ");
    encrypted_message.data = encrypted_data_bytes;
    encrypted_message.size = strlen(encrypted_data_hex.c_str())/2;

    printf("Server: Sending encrypted data to the enclave...\n");
    result = decrypt_dataset_and_set_data(*enclave, &ret, &encrypted_message);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Server: decrypt_dataset_and_set_data failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    if (encrypted_message.data)
    {
        free(encrypted_message.data);
    }

    gettimeofday(&t1, 0);
    time_map->items["06_elapsed_decrypt_set_data"] = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;

    // 9. call to the enclave to get the actual computation result
    gettimeofday(&t0, 0);
    result = do_computation(*enclave, &ret);
    gettimeofday(&t1, 0);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Server: do_computation failed. %s", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    elapsed_computation_result = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;
    printf("Server: computation_result time (microseconds): %lld\n", elapsed_computation_result);
    time_map->items["07_elapsed_computation_result"] = elapsed_computation_result;

    // 5. get the signed output
    printf("Server: Requesting the signed output from the enclave...\n");
    gettimeofday(&t0, 0);
    result = get_signed_output(*enclave, &ret, &signed_output);
    gettimeofday(&t1, 0);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Server: get_signed_output failed. %s", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    elapsed_signature = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;
    printf("Server: signed output time (microseconds): %lld\n", elapsed_signature);
    time_map->items["08_elapsed_signature"] = elapsed_signature;

    // 10. return the output to the client
    gettimeofday(&t0, 0);
    output_json["hash_input_data"] = convertBytesToHex(signed_output.hash_input_data, 32);
    output_json["hash_output_data"] = convertBytesToHex(signed_output.hash_output_data, 32);
    output_json["output_data"] = convertBytesToHex(signed_output.output_data, signed_output.size_output_data);
    output_json["signature"] = convertBytesToHex(signed_output.signature, 256);

    output_json_str = output_json.dump(4);

    send_data(client_socket, output_json_str.c_str());
    gettimeofday(&t1, 0);
    time_map->items["09_elapsed_send_output"] = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;

    ret = 0;

exit:
    return ret;
}

int main(int argc, const char* argv[])
{
    // server related
	int server_socket, client_socket;
	struct sockaddr_storage client_address;
	socklen_t sin_size;
	char s[INET6_ADDRSTRLEN];

    // main server logic
    // 1. open socket and wait connection
    server_socket = setup_server_socket();
	if (listen(server_socket, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}
	printf("server: waiting for connections...\n");

    // server loop
    // TODO: loop body
    // 2. for each request:
    // 2.0 check request id. if present in request -> enclave mapping
    // 2.0.1 get parameters
    // 2.0.1.1 get encrypted data and pass it to the enclave OR
    // 2.0.1.2 get signed output and return

    // 2.1 if not present in mapping, generate a request id
    // 2.1.1. get parameters: enclave type
    // 2.1.2 launch enclave
    // 2.1.3 store request id -> enclave mapping
    // 2.1.4 return quote with request id
	while(1)
    {
		sin_size = sizeof(client_address);
		client_socket = accept(server_socket, (struct sockaddr *)&client_address, &sin_size);
		if (client_socket == -1) {
			perror("accept");
			continue;
		}

    	inet_ntop(client_address.ss_family, get_in_addr((struct sockaddr *)&client_address), s, sizeof(s));

		printf("server: got connection from %s\n", s);

        int pid = fork();
		if (pid == 0) 
		{   
			close(server_socket);
			
            uuid_t binuuid;

            // enclave related
            oe_enclave_t* enclave = NULL;
            oe_result_t result = OE_OK;

            int ret = 1;

            oe_report_t parsed_report = {0};

            uint8_t* pem_key = NULL;
            size_t pem_key_size = 0;
            uint8_t* remote_report = NULL;
            size_t remote_report_size = 0;

            json quote_json;
            std::string quote_json_str;

            timings time_map;

            struct timeval t0;
            struct timeval t1;
            struct timeval t_start;
            struct timeval t_end;
            long long t_elapsed_request, elapsed_quote, elapsed_handle_one_batch;

            gettimeofday(&t_start, 0);

            char* enclave_path;

            gettimeofday(&t0, 0);
            // 1. generate uuid for the request
            uuid_generate_random(binuuid);
            char *uuid = (char*) malloc(UUID_STR_LEN + 1);
            uuid_unparse(binuuid, uuid);
            uuid[UUID_STR_LEN-1] = '\0';
            printf("Request uuid: %s\n", uuid);

            /*
            char* stats_filename = (char*) malloc(STATS_FILENAME_LEN);
            memcpy(stats_filename, "stats_", 6);
            memcpy(stats_filename + 6, uuid, UUID_STR_LEN);
            memcpy(stats_filename + 42, ".txt", 4);
            stats_filename[STATS_FILENAME_LEN-1] = '\0';

            printf("stats_filename: %s\n", stats_filename);
            */

            // 2. get the enclave request type
            char* buf = receive_data(client_socket);
            //printf("Received: %s\n", buf);

            auto jreq = json::parse(buf);
            free(buf);

            std::string requested_computation = json::parse(to_string(jreq["RequestedComputation"]));
            std::string requested_mode = json::parse(to_string(jreq["RequestedMode"]));

            if (requested_computation == "sampling")
            {
                enclave_path = (char*) malloc(strlen(ENCLAVE_SAMPLING_PATH) + 1);
                memcpy(enclave_path, ENCLAVE_SAMPLING_PATH, strlen(ENCLAVE_SAMPLING_PATH));
                enclave_path[strlen(ENCLAVE_SAMPLING_PATH)] = '\0';
            }
            else if (requested_computation == "statistics")
            {
                enclave_path = (char*) malloc(strlen(ENCLAVE_STATISTICS_PATH) + 1);
                memcpy(enclave_path, ENCLAVE_STATISTICS_PATH, strlen(ENCLAVE_STATISTICS_PATH));
                enclave_path[strlen(ENCLAVE_STATISTICS_PATH)] = '\0';
            }
            else if (requested_computation == "sampling_statistics")
            {
                enclave_path = (char*) malloc(strlen(ENCLAVE_SAMPLING_STATISTICS_PATH) + 1);
                memcpy(enclave_path, ENCLAVE_SAMPLING_STATISTICS_PATH, strlen(ENCLAVE_SAMPLING_STATISTICS_PATH));
                enclave_path[strlen(ENCLAVE_SAMPLING_STATISTICS_PATH)] = '\0';
            }
            else if (requested_computation == "nonrepetition_sampling")
            {
                enclave_path = (char*) malloc(strlen(ENCLAVE_NONREPETITION_SAMPLING_PATH) + 1);
                memcpy(enclave_path, ENCLAVE_NONREPETITION_SAMPLING_PATH, strlen(ENCLAVE_NONREPETITION_SAMPLING_PATH));
                enclave_path[strlen(ENCLAVE_NONREPETITION_SAMPLING_PATH)] = '\0';
            }
            else if (requested_computation == "custom")
            {
                // receive the enclave binary
                std::string enclave_buf_hex = json::parse(to_string(jreq["CustomEnclaveHex"]));
                uint8_t* enclave_buf = convertHexToBytes(enclave_buf_hex.c_str(), strlen(enclave_buf_hex.c_str()));
                //printf("len enclave_buf_hex: %ld\n", strlen(enclave_buf_hex.c_str()));
                // store the enclave binary under /tmp/enclave.signed_<uuid>
                enclave_path = (char*) malloc(20 + UUID_STR_LEN + 1);
                memcpy(enclave_path, "/tmp/enclave.signed_", 20);
                memcpy(enclave_path+20, uuid, UUID_STR_LEN);
                enclave_path[20+UUID_STR_LEN] = '\0';

                FILE *file_enclave = fopen(enclave_path, "wb");
                fwrite(enclave_buf, strlen(enclave_buf_hex.c_str())/2, 1, file_enclave);
                fclose(file_enclave);
                free(enclave_buf);
            }
            else
            {
                printf("Unsupported computation type: %s\n", requested_computation.c_str());
                close(client_socket);
                exit(0);
            }
            gettimeofday(&t1, 0);
            time_map.items["01_elapsed_receive_parse_request"] = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;

            // 3. initialize the enclave and get the quote
            printf("Server: Requesting the enclave to do the computation (requested_computation: %s)...\n", requested_computation.c_str());
            ret = create_enclave_and_get_quote(enclave_path, &enclave, &parsed_report, &pem_key, &pem_key_size, &remote_report, &remote_report_size, &time_map);

            gettimeofday(&t0, 0);
            quote_json["Type"] = (int) parsed_report.type;
            quote_json["MrEnclaveHex"] = convertBytesToHex(parsed_report.identity.unique_id, OE_UNIQUE_ID_SIZE);
            quote_json["MrSignerHex"] = convertBytesToHex(parsed_report.identity.signer_id, OE_SIGNER_ID_SIZE);
            quote_json["ProductIdHex"] = convertBytesToHex(parsed_report.identity.product_id, OE_PRODUCT_ID_SIZE);
            quote_json["SecurityVersion"] = (int) parsed_report.identity.security_version;
            quote_json["Attributes"] = (int) parsed_report.identity.attributes;
            quote_json["QuoteHex"] = convertBytesToHex(remote_report, remote_report_size);
            quote_json["EnclaveHeldDataHex"] = convertBytesToHex(pem_key, pem_key_size);
            
            quote_json_str = quote_json.dump(2);

            // 4. send the uuid to the client
            send_data(client_socket, uuid);

            // 5. send the quote to the client
            send_data(client_socket, quote_json_str.c_str());
            gettimeofday(&t1, 0);
            time_map.items["04_elapsed_get_send_quote"] = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;

            // 6. receive more data from the client to be passed to the enclave
            if (requested_mode == "static")
            {
                gettimeofday(&t0, 0);
                ret = handle_one_batch_data(client_socket, &enclave, &pem_key, &pem_key_size, NULL, &time_map);
                gettimeofday(&t1, 0);
                elapsed_handle_one_batch = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;
                printf("elapsed_handle_one_batch: %lld\n", elapsed_handle_one_batch);
            }
            else if (requested_mode == "dynamic")
            {
                bool should_stop = false;
                while (!should_stop)
                {
                    gettimeofday(&t0, 0);
                    ret = handle_one_batch_data(client_socket, &enclave, &pem_key, &pem_key_size, &should_stop, &time_map);
                    gettimeofday(&t1, 0);
                    elapsed_handle_one_batch = (t1.tv_sec-t0.tv_sec)*1000000LL + t1.tv_usec-t0.tv_usec;
                    printf("elapsed_handle_one_batch: %lld\n", elapsed_handle_one_batch);
                }
            }
            gettimeofday(&t_end, 0);

            t_elapsed_request = (t_end.tv_sec-t_start.tv_sec)*1000000LL + t_end.tv_usec-t_start.tv_usec;
            time_map.items["99_elapsed_total_request"] = t_elapsed_request;
            printf("Server: elapsed total request time (microseconds): %lld\n", t_elapsed_request);

            if (requested_mode == "static")
            {
                std::string s = time_map.items.dump(4);
                //printf("time_map: %s\n", s.c_str());
                send_data(client_socket, s.c_str());
                /*
                char* stats_full_filename = (char*) malloc(strlen(STATS_DIR) + strlen(stats_filename) + 1 + 1);
                memcpy(stats_full_filename, STATS_DIR, strlen(STATS_DIR));
                memcpy(stats_full_filename + strlen(STATS_DIR), "/", 1);
                memcpy(stats_full_filename + strlen(STATS_DIR) + 1, stats_filename, strlen(stats_filename));
                stats_full_filename[strlen(STATS_DIR) + strlen(stats_filename) + 1] = '\0';
                FILE* f_stats = fopen(stats_full_filename, "w");
                fprintf(f_stats, "%s", s.c_str());
                fclose(f_stats);
                free(stats_full_filename);
                */
            }

            free(uuid);
            //free(stats_filename);
            free(enclave_path);

            printf("Server: Successfully handled request\n");
            printf("===============================\n");

            if (enclave)
                terminate_enclave(enclave);

            ret = 0;

            close(client_socket);
            exit(0);
        }
		else if (pid > 0)
		{
    		close(client_socket);
		}
    }

}
