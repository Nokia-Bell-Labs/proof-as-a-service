# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import base64
import json
import os
import sys
import socket
import struct
import time

from azure.identity import DefaultAzureCredential
from azure.security.attestation import AttestationClient, AttestationToken, AttestationResult

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAA_URL="https://sharedneu.neu.attest.azure.net"

PORT = 3490

# num items per second
BATCH_RATE = int(os.getenv("BATCH_RATE", 1000))
# num batches per second
BATCH_FREQUENCY = float(os.getenv("BATCH_FREQUENCY", 1))

BATCH_SIZE = int(BATCH_RATE / BATCH_FREQUENCY)
BATCH_SLEEP = 1 / BATCH_FREQUENCY

BATCH_DATA_MIN = 0
BATCH_DATA_MAX = 10000

NUM_BATCHES = int(os.getenv("NUM_BATCHES", 100))

BUFFER_SIZE = 4

# send data in a loop
def send_data(client_socket, data):
    data_bytes = json.dumps(data).encode('utf-8')
    #print(data_bytes[:10])
    #print("sending", len(data_bytes), "bytes...", data_bytes[-10:])
    data_size = struct.pack('<Q', len(data_bytes))
    #data_size = len(data_bytes)
    #print(len(data_size))

    client_socket.send(data_size)

    num_send = int(len(data_bytes) / BUFFER_SIZE)
    num_rem = len(data_bytes) % BUFFER_SIZE
    num_total = 0
    #print(num_send, num_rem)
    pos = 0
    for i in range(num_send):
        client_socket.send(data_bytes[pos:pos+BUFFER_SIZE])
        pos += BUFFER_SIZE
        num_total += BUFFER_SIZE

    if num_rem > 0:
        #print(data_bytes[pos:pos+num_rem])
        client_socket.send(data_bytes[pos:pos+num_rem])
        num_total += num_rem

    #print("total:", num_total, "expected:", len(data_bytes))


# receive data in a loop
def receive_data(client_socket):
    received_msg = client_socket.recv(8)
    data_size = struct.unpack('<Q', received_msg[0:8])[0]
    #print("expecting", data_size, "bytes...")

    #data = client_socket.recv(data_size).decode()
    data = bytearray()
    num_recv = int(data_size / BUFFER_SIZE)
    num_rem = data_size % BUFFER_SIZE

    for i in range(num_recv):
        buf = client_socket.recv(BUFFER_SIZE)
        data.extend(buf)

    if num_rem > 0:
        buf = client_socket.recv(num_rem)
        data.extend(buf)

    data = data.decode()
    #print('Received from server: ' + data)

    return data

def verify_quote(quote):
    #print("============ Verifying quote from enclave")

    # python implementation rather than the dotnet
    # use the internal checks to validate the token's properties (rather than our incomplete minimal validatation above)
    attest_client = AttestationClient(
        endpoint=MAA_URL,
        credential=DefaultAzureCredential(),
        validate_token=True,
        validate_signature=True,
        validate_issuer=True,
        issuer=MAA_URL,
        validate_expiration=True,
        #validation_callback=validate_token
        )

    #print("The following certificate signers are responsible for the token's validity:")
    #signers = attest_client.get_signing_certificates()
    #for signer in signers:
    #    cert = cryptography.x509.load_pem_x509_certificate(signer.certificates[0].encode('ascii'), backend=default_backend())
    #    print('Certification issuer:', cert.issuer, '; subject:', cert.subject)

    response, token = attest_client.attest_open_enclave(bytearray.fromhex(quote["QuoteHex"]), runtime_data=bytearray.fromhex(quote["EnclaveHeldDataHex"]))
    
    #print(response)
    #property_names=[p for p in dir(AttestationResult) if isinstance(getattr(AttestationResult,p),property)]
    #for prop in property_names:
    #    print(prop + ": " + str(getattr(response, prop)))

    #print(token)

    '''
    property_names=[p for p in dir(AttestationToken) if isinstance(getattr(AttestationToken,p),property)]
    for prop in property_names:
        print(prop + ": " + str(getattr(token, prop)))
    '''

    #print("Issuer of token is: ", response.issuer)
    #print("Enclave held data (enclave's public key): ", str(response.enclave_held_data))

    return response

def verify_computation_result(computation_result, enclave_public_key, private_data):
    #print("============ Verifying computation_result from enclave")

    # check the hash_input_data with the local computation 
    # to ensure that the host did not interfere with the data while passing it to the enclave 
    # (e..g, drop some hashes, modify them)
    # this would not be an issue if we had the encryption between the client and the enclave
    # because the host would not see it
    # (the check can still be done for additional integrity checks)

    verified = False

    print("[?] Checking if the host interfered with the input data before passing it to the enclave...")

    hash_original_input_data = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_original_input_data.update(bytearray(private_data))
    hash_original_input_data = hash_original_input_data.finalize()

    if hash_original_input_data.hex() != computation_result["hash_input_data"]:
        print("--[NOT OK] The hashes of the input data DO NOT MATCH.")
        return verified

    print("[OK] The hashes of the input data MATCH.")
    print("[?] Verifying the signature from the enclave...")

    signature_input = bytearray.fromhex(computation_result["hash_input_data"]) + bytearray.fromhex(computation_result["hash_output_data"])
    chosen_hash = hashes.SHA256()
    digest = hashes.Hash(chosen_hash, backend=default_backend())
    digest.update(signature_input)
    digest = digest.finalize()
    
    signature = bytes.fromhex(computation_result["signature"])

    try:
        enclave_public_key.verify(signature, digest, padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=32), utils.Prehashed(chosen_hash))
        verified = True
    except Exception as exc:
        pass

    return verified

def setup_remote_enclave(client_socket, requested_computation, requested_mode, custom_enclave_filename, time_map):
    # 1. send request about enclave
    t_start = time.time()
    req = {}
    req["RequestedComputation"] = requested_computation
    req["RequestedMode"] = requested_mode

    if requested_computation == "custom":
        f = open(custom_enclave_filename, "rb")
        enclave_data = f.read()
        f.close()
        req["CustomEnclaveHex"] = enclave_data.hex()

    send_data(client_socket, req)

    # 2. receive uuid and quote
    uuid_data = receive_data(client_socket)
    print(uuid_data)
    quote_data = receive_data(client_socket)
    time_map["01_elapsed_setup_remote_enclave"] = (time.time() - t_start) * 1000.0

    t_start = time.time()

    quote = json.loads(quote_data)

    # 3. verify quote
    print("[?] Verifying the enclave quote and getting the attestation result...")
    
    try:
        attestation_result = verify_quote(quote)
        print("[OK] Enclave quote verification passed and attestation successful.")
    except Exception as exc:
        print("[NOT OK] Enclave quote verification failed.")
        return False
    time_map["02_elapsed_verify_quote"] = (time.time() - t_start) * 1000.0

    t_start = time.time()
    with open("received/" + str(uuid_data) + "_quote.json", "w") as f_quote:
        f_quote.write(quote_data)
    time_map["03_elapsed_store_quote"] = (time.time() - t_start) * 1000.0

    # 4. extract enclave public key
    t_start = time.time()
    enclave_public_key_bytes = bytes.fromhex(quote["EnclaveHeldDataHex"])
    i = 0
    for b in enclave_public_key_bytes:
        if b == 0:
            break
        i += 1
    enclave_public_key_data = enclave_public_key_bytes[0:i]
    enclave_public_key = serialization.load_pem_public_key(enclave_public_key_data, default_backend())
    time_map["04_elapsed_extract_pub_key"] = (time.time() - t_start) * 1000.0

    return True, uuid_data, attestation_result, enclave_public_key

def xor_encrypt_data(private_data, session_key_bytes):
    encrypted_data = bytearray()
    i = 0
    for pd in private_data:
        x = pd ^ session_key_bytes[i%32]
        #print(pd, "XOR", session_key_bytes[i%32], "=", x)
        i+=1
        encrypted_data.append(x)

    encrypted_data = bytes(encrypted_data)

    return encrypted_data

def xor_decrypt_data(encrypted_data, session_key_bytes):
    decrypted_data = bytearray()
    i = 0
    for ed in encrypted_data:
        x = ed ^ session_key_bytes[i%32]
        #print(ed, "XOR", session_key_bytes[i%32], "=", x)
        i+=1
        decrypted_data.append(x)

    decrypted_data = bytes(decrypted_data)
    return decrypted_data

def handle_one_batch_data(client_socket, uuid_data, enclave_public_key, private_data, session_key_bytes, encrypted_session_key, batch_num, should_stop, time_map):
    # 6. encrypt private data with session key
    # encrypt the data with XOR: each byte should be XORed with the session key bytes
    # when session key bytes over then need to start over
    t_start = time.time()
    encrypted_data = xor_encrypt_data(private_data, session_key_bytes)
    time_map["07_elapsed_encrypt_private_data"] = (time.time() - t_start) * 1000.0

    # 6. send new request with encrypted session key and encrypted data
    t_start = time.time()
    req2 = {}
    req2["EncryptedSessionKey"] = encrypted_session_key.hex()
    req2["EncryptedData"] = encrypted_data.hex()
    req2["ShouldStop"] = should_stop

    send_data(client_socket, req2)

    computation_result_data = receive_data(client_socket)
    time_map["08_elapsed_communication_computation"] = (time.time() - t_start) * 1000.0

    if computation_result_data == "" and should_stop:
        print("No more data from the server.")
        return

    computation_result = json.loads(computation_result_data)

    t_start = time.time()
    verified = verify_computation_result(computation_result, enclave_public_key, private_data)
    time_map["09_elapsed_signature_verification"] = (time.time() - t_start) * 1000.0
    if verified:
        print("[OK] Successfully verified signature of the enclave output.")
    else:
        print("[ERROR] Signature verification of the enclave output failed.")

    with open("received/" + str(uuid_data) + "_result_" + "{0:03d}".format(batch_num) + ".json", "w") as f_computation_result:
        f_computation_result.write(computation_result_data)
    
    if requested_computation in ["statistics", "sampling_statistics"]:
        print_output(computation_result, requested_computation)

def print_output(computation_result, requested_computation):
    if requested_computation == "sampling":
        output_data_bytes = bytes.fromhex(computation_result["output_data"])
        #print(output_data_bytes.decode().split("\n"))

    elif requested_computation == "statistics":
        output_data_bytes = bytes.fromhex(computation_result["output_data"])
        min_val = struct.unpack('i', output_data_bytes[0:4])[0]
        max_val = struct.unpack('i', output_data_bytes[5:9])[0]
        mean_val = struct.unpack('d', output_data_bytes[10:18])[0]
        sum_val = struct.unpack('i', output_data_bytes[19:23])[0]

        p10_val = struct.unpack('i', output_data_bytes[24:28])[0]
        p25_val = struct.unpack('i', output_data_bytes[29:33])[0]
        p50_val = struct.unpack('i', output_data_bytes[34:38])[0]
        p75_val = struct.unpack('i', output_data_bytes[39:43])[0]
        p90_val = struct.unpack('i', output_data_bytes[44:48])[0]
        p95_val = struct.unpack('i', output_data_bytes[49:53])[0]
        p99_val = struct.unpack('i', output_data_bytes[54:58])[0]

        print("min:", min_val, ", max:", max_val, ", mean:", mean_val, ", sum:", sum_val)
        print("percentiles:", p10_val, p25_val, p50_val, p75_val, p90_val, p95_val, p99_val)

    elif requested_computation == "sampling_statistics":
        output_data_bytes = bytes.fromhex(computation_result["output_data"])
        size_output = len(output_data_bytes)
        output_data = [struct.unpack('i', output_data_bytes[i:i+4])[0] for i in range(0, size_output, 4)]
        output_data.sort()
        #print(output_data)

        output_data_bytes = bytes.fromhex(computation_result["output_data"])
        mean_val = struct.unpack('d', output_data_bytes[0:8])[0]

        p10_val = struct.unpack('i', output_data_bytes[9:13])[0]
        p25_val = struct.unpack('i', output_data_bytes[14:18])[0]
        p50_val = struct.unpack('i', output_data_bytes[19:23])[0]
        p75_val = struct.unpack('i', output_data_bytes[24:28])[0]
        p90_val = struct.unpack('i', output_data_bytes[29:33])[0]
        p95_val = struct.unpack('i', output_data_bytes[34:38])[0]
        p99_val = struct.unpack('i', output_data_bytes[39:43])[0]

        print("mean:", mean_val)
        print("percentiles:", p10_val, p25_val, p50_val, p75_val, p90_val, p95_val, p99_val)

    elif requested_computation == "nonrepetition_sampling":
        output_data_bytes = bytes.fromhex(computation_result["output_data"])
        #output_data = output_data_bytes.decode().split("\n")
        #output_data = [sample for sample in output_data if sample != ""]
        #print(output_data)

    elif requested_computation == "custom":
        # this would need to be updated according to any custom logic
        # here, we just dump the output_data
        #output_data_bytes = bytes.fromhex(computation_result["output_data"])
        #print(output_data_bytes.decode())

        output_data_bytes = bytes.fromhex(computation_result["output_data"])
        mean_val = struct.unpack('d', output_data_bytes[0:8])[0]

        p10_val = struct.unpack('i', output_data_bytes[9:13])[0]
        p25_val = struct.unpack('i', output_data_bytes[14:18])[0]
        p50_val = struct.unpack('i', output_data_bytes[19:23])[0]
        p75_val = struct.unpack('i', output_data_bytes[24:28])[0]
        p90_val = struct.unpack('i', output_data_bytes[29:33])[0]
        p95_val = struct.unpack('i', output_data_bytes[34:38])[0]
        p99_val = struct.unpack('i', output_data_bytes[39:43])[0]

        print("mean:", mean_val)
        print("percentiles:", p10_val, p25_val, p50_val, p75_val, p90_val, p95_val, p99_val)


def client_program(server_address, params):
    summary = {}
    time_map = {}
    custom_enclave_filename = None

    requested_computation = params["requested_computation"]
    if requested_computation == "custom":
        custom_enclave_filename = params["custom_enclave_filename"]

    summary["requested_computation"] = requested_computation

    requested_mode = params["requested_mode"]

    client_socket = socket.socket()
    client_socket.setblocking(True)
    client_socket.connect((server_address, PORT))

    t_start_all = time.time()
    # setup remote enclave
    success, uuid_data, attestation_result, enclave_public_key = setup_remote_enclave(client_socket, requested_computation, requested_mode, custom_enclave_filename, time_map)
    summary["uuid"] = str(uuid_data)
    if not success:
        print("[ERROR] setup_remote_enclave failed.")

    print("[OK] Remote enclave initiated and successfully verified.")

    # 5. generate session key and encrypt it with enclave's public key
    t_start = time.time()
    session_key_bytes = os.urandom(32)
    #print(session_key_bytes.hex())
    encrypted_session_key = enclave_public_key.encrypt(
        session_key_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    #print(encrypted_session_key.hex())
    time_map["05_elapsed_generate_encrypted_session_key"] = (time.time() - t_start) * 1000.0

    if requested_mode == "static":
        private_data_filename = params["private_data_filename"]
        summary["data_filename"] = private_data_filename

        t_start_data = time.time()
        with open(private_data_filename, "rb") as f_data:
            private_data = f_data.read()
        time_map["06_elapsed_read_private_data"] = (time.time() - t_start_data) * 1000.0

        handle_one_batch_data(client_socket, uuid_data, enclave_public_key, private_data, session_key_bytes, encrypted_session_key, 0, False, time_map)

        server_stats_data = receive_data(client_socket)
        summary["server_stats"] = json.loads(server_stats_data)

    elif requested_mode == "dynamic":
        import random
        time_map["80_dynamic_elapsed"] = {}
        summary["batch_size"] = BATCH_SIZE
        summary["batch_frequency"] = BATCH_FREQUENCY
        summary["num_batches"] = NUM_BATCHES
        # loop
        # 1. generate some dummy data
        # 2. encrypt and send
        # 3. receive and verify computation_result
        for i in range(NUM_BATCHES):
            batch = []
            t_start = time.time()
            for j in range(BATCH_SIZE):
                val = random.randint(BATCH_DATA_MIN, BATCH_DATA_MAX)
                batch.append(str(val) + "\n")
            private_data = bytes(''.join(batch).encode('utf-8'))
            t_data_gen = time.time() - t_start

            t_start_batch = time.time()
            handle_one_batch_data(client_socket, uuid_data, enclave_public_key, private_data, session_key_bytes, encrypted_session_key, i, False, time_map)
            t_batch = time.time() - t_start_batch
            time_map["80_dynamic_elapsed"]["batch_" + "{0:03d}".format(i)] = t_batch * 1000.0
            print("batch num:", i, "elapsed:", t_batch * 1000.0)

            if i < NUM_BATCHES - 1:
                sleep_time = BATCH_SLEEP - t_data_gen - t_batch
                if sleep_time < 0:
                    sleep_time = 0
                print("sleeping for:", sleep_time, t_data_gen, t_batch)
                time.sleep(sleep_time)

        batch = []
        private_data = bytes(''.join(batch).encode('utf-8'))
        handle_one_batch_data(client_socket, uuid_data, enclave_public_key, private_data, session_key_bytes, encrypted_session_key, i, True, time_map)

        for key in ["07_elapsed_encrypt_private_data", "08_elapsed_communication_computation", "09_elapsed_signature_verification"]:
            del time_map[key]

    time_map["99_t_all"] = (time.time() - t_start_all) * 1000.0
    summary["client_stats"] = time_map

    print(json.dumps(summary, indent=4))
    with open("received/" + str(uuid_data) + "_summary.json", "w") as f_summary:
        f_summary.write(json.dumps(summary, indent=4))

    client_socket.close()


if __name__ == '__main__':
    server_address = sys.argv[1]
    requested_computation = sys.argv[2]
    requested_mode = sys.argv[3]
    private_data_filename = sys.argv[4]
    custom_enclave_filename = sys.argv[5]

    params = {}
    params["requested_mode"] = requested_mode
    params["requested_computation"] = requested_computation
    params["private_data_filename"] = private_data_filename
    params["custom_enclave_filename"] =  custom_enclave_filename

    os.makedirs("received", exist_ok=True)
    client_program(server_address, params)
