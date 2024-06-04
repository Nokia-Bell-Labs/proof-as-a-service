# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import base64
import io
import json
import os
import sys
import uuid
import requests
import zipfile

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from functools import singledispatch

from azure.identity import DefaultAzureCredential
from azure.security.attestation import AttestationClient, AttestationToken, AttestationResult

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ATTESTATION_SERVICE_URL = "https://sharedcus.cus.attest.azure.net"

class SGXProof():
    def __init__(self, attestation_service_url):
        self._proof = {}
        self._proof["proof_type"] = "SGX"
        self._proof["attestation_service_url"] = attestation_service_url
        
    def set_enclave_quote_and_public_key(self, quote, public_key):
        self._proof["enclave_quote"] = quote
        self._proof["enclave_public_key"] = public_key
    
    def set_enclave_code_hash_and_signature(self, code_hash, signature):
        self._proof["enclave_code_hash"] = code_hash
        self._proof["enclave_code_hash_signature"] = signature

    def set_enclave_output_and_signature(self, output, signature):
        self._proof["enclave_output"] = output
        self._proof["enclave_signature"] = signature

    def dump_proof(self, filename):
        serialized_proof = json.dumps(self._proof, sort_keys=True)

        with open(filename, "w") as f:
            f.write(serialized_proof)
    


def verify_quote(quote, enclave_key):
    #print("============ Verifying quote from enclave")

    # python implementation rather than the dotnet
    # use the internal checks to validate the token's properties (rather than our incomplete minimal validatation above)
    attest_client = AttestationClient(
        endpoint=ATTESTATION_SERVICE_URL,
        credential=DefaultAzureCredential(),
        validate_token=True,
        validate_signature=True,
        validate_issuer=True,
        issuer=ATTESTATION_SERVICE_URL,
        validate_expiration=True,
        #validation_callback=validate_token
        )

    response, token = attest_client.attest_sgx_enclave(quote, runtime_data=enclave_key)

    return response

def print_sep(text: str):
    sep = '*'
    text_str = sep*5 + ' ' + text + ' ' + sep*5
    text_str_len = len(text_str)
    #print('[PraaS-Client] ' + sep*text_str_len)
    print('[PraaS-Client]')
    print('[PraaS-Client] ' + text_str)

def b64_str_to_bytes(b64_str) -> bytes:
    #return base64.decodebytes(str_base64.encode('utf-8'))
    return base64.b64decode(b64_str)

def decode_if_base64(value):
    try:
        decoded_value = base64.b64decode(value)
        return decoded_value
    except:
        # if an exception is raised during decoding, return the original value
        return value

def bytes_to_base64(data: bytes) -> bytes:
    return base64.b64encode(data)

# Convert bytes object to serializble string representation
def bytes_to_base64_str(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

# Encrypt with an RSA public key
def encrypt_with_pub_key(data: bytes, public_key: bytes) -> bytes:
    cipher = load_pem_public_key(public_key, default_backend()).encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher

def verify_with_pub_key(data: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        load_pem_public_key(public_key, default_backend()).verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except rsa.InvalidSignature:
        return False

# Encrypt data with Fernet recipe
@singledispatch
def encrypt_fernet(data: bytes, symmetric_key: bytes) -> bytes:
    f = Fernet(symmetric_key)
    return f.encrypt(data)

@encrypt_fernet.register(str)
def _(data: str, symmetric_key: bytes):
    f = Fernet(symmetric_key)
    return f.encrypt(data.encode())

# Decrypt data with Fernet recipe
def decrypt_fernet(encrypted_data: bytes, key) -> bytes:
    f = Fernet(key)
    return f.decrypt(encrypted_data)

# Create zip file
def zip_files(path_to_files) -> bytes:
    path = os.path.normpath(path_to_files)
    #print(f'PATH: {path_to_files}')
    zip_bytes = io.BytesIO()
    with zipfile.ZipFile(zip_bytes, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                print(f'[PraaS-Client] Adding file to zip: {file_path}')
                zip_path = file_path[len(path):]  # Strip off the path prefix from the full file name
                zip_file.write(file_path, arcname=zip_path)
    return zip_bytes.getvalue()

# Zip files and encrypt zip 
def zip_n_encrypt(path_to_files, symmetric_key) -> bytes:
    # Zip all files in the specified directory
    path = os.path.normpath(path_to_files)
    #print(f'PATH: {path_to_files}')
    zip_bytes = io.BytesIO()
    with zipfile.ZipFile(zip_bytes, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                print(f'[PraaS-Client] Adding file to zip: {file_path}')
                zip_path = file_path[len(path):]  # Strip off the path prefix from the full file name
                zip_file.write(file_path, arcname=zip_path)
    # Encrypt the zip file with the server's public key
    #print(f'zip: {zip_bytes.getvalue()}')
    encrypted_zip_bytes = encrypt_fernet(zip_bytes.getvalue(), symmetric_key)
    return encrypted_zip_bytes

def dump_response(response: requests.Response):
    content_type = response.headers['content-type']
    print(F'[PraaS-Client] Response:')
    print(f"     Status Code:  {response.status_code} ")
    print(f'     Message:      {response.text}')
    print(f"     Content-Type: {response.headers['content-type']}")
    
# Send data
def call_api(base_url, data = None, uuid = None, method = None) -> requests.Response:
    if uuid:
        url = f'{base_url}/{uuid}/{method}'
    else:
        url = base_url
    json_data = json.dumps(data)
    response = requests.post(url, data=json_data, headers={'content-type': 'application/json'})
    print(f'[PraaS-Client] Request:  {json_data[0:1024]}')
    return response

# Request a new enclave from the server
def request_enclave(url, requested_type: str):
    req = {}
    req["type"] = requested_type
    response = call_api(url, data=req)
    if response.status_code != 200:
        return None, None, None
    server_data = response.json()
    id = uuid.UUID(server_data["uuid"])
    quote = b64_str_to_bytes(server_data["quote"])
    pubkey = server_data["key"].encode() 
    return id, pubkey, quote

# Request the SGX quote from the server
def request_quote(url, enclave_id, data) -> bytes:
    api_method = "quote"
    req = {'enclave_id': enclave_id.urn, 'method': 'quote'}
    response_data = call_api(url, data=req, uuid=enclave_id, method=api_method)
    server_data = response_data.json()
    quote = b64_str_to_bytes(server_data["data"])
    return quote

def dump_quote(quote: bytes) -> None:
    print(f"[PraaS-Client] Received SGX quote with size = {len(quote)} and the following fields:")
    print(' '*2 + '-'*82)
    if len(quote) > 0: 
        print(f"  ATTRIBUTES.FLAGS: {quote[96:104].hex()}  [ Debug bit: {quote[96] & 2 > 0} ]")
        print(f"  ATTRIBUTES.XFRM:  {quote[104:112].hex()}")
        print(f"  MRENCLAVE:        {quote[112:144].hex()}")
        print(f"  MRSIGNER:         {quote[176:208].hex()}")
        print(f"  ISVPRODID:        {quote[304:306].hex()}")
        print(f"  ISVSVN:           {quote[306:308].hex()}")
        print(f"  REPORTDATA:       {quote[368:400].hex()}")
        print(f"                    {quote[400:432].hex()}")
    print(' '*2 + '-'*82)

# Get the server's public key
def request_key(url, enclave_id, data) -> bytes:
    api_method = "key"
    req = {'enclave_id': enclave_id.urn, 'method': 'key'}
    response_data = call_api(url, data=req, uuid=enclave_id, method=api_method)
    server_data = response_data.json()
    key = server_data["data"].encode()
    #key = decode_to_bytes(server_data["data"])
    return key

# Send the python script and all modukes as zip to teh server.  
def upload_code(url, enclave_id, data: dict) -> dict:
    api_method = "code"
    response_data = call_api(url, data, enclave_id, api_method)
    return response_data

# Entrypoint
def client_program(url, params) -> None:

    proof = SGXProof(ATTESTATION_SERVICE_URL)

    requested_type = params["type"]
    code_path = params["path"]
    modulename = params["module"]
    functionname = params["function"]
    
    # Request an enclave
    print_sep('ENCLAVE REQUEST')
    
    files = {}
    #files['zip'] = zip_files(code_path)
    with open(code_path + '/requirements.txt', 'rb') as file:
        files['pip'] = file.read()
    #payload = {'type': requested_type, 'my_zip': code_path}
    payload = {'type': requested_type}
    data = {'json': json.dumps(payload)}
    response = requests.post(url, files=files, data=data)
    
    print(F'[PraaS-Client] Response:')
    print(f"     Status Code:  {response.status_code} ")
    print(f'     Message:      {response.text}')
    print(f"     Content-Type: {response.headers['content-type']}")
    
    resp_json = response.json()
    enclave_id = resp_json['id']
    
    quote = b64_str_to_bytes(resp_json['quote'])
    dump_quote(quote)
    enclave_key = resp_json['key'].encode()
    try:
        verify_quote(quote, enclave_key)
        print("SUCCESSFULLY VERIFIED QUOTE")
    except Exception as exc:
        raise
    
    # Verify the enclave's public key
    print_sep('VERIFYING ENCLAVE KEY')
    try:
        # - Calculate the hash of the received key
        key_hash_calc = hashes.Hash(hashes.SHA256())
        key_hash_calc.update(enclave_key)
        calculated_hash_digest = key_hash_calc.finalize()
        print(f'   calc hash digest:  {calculated_hash_digest.hex()}')
    except Exception as e:
        print(e)
        pass
    
    try:
        # - Extract the hash of the enclave's public key from the quote
        #enclave_quote = request_quote(url, id, "empty data")
        key_hash_recvd = quote[368:400]
        print(f'   quote hash digest: {key_hash_recvd.hex()}')
        if calculated_hash_digest == key_hash_recvd:
            verification_str = "succeeded [OK]"
        else:
            verification_str = "failed [ERROR]"
        print(f"[PraaS-Client] Key verification {verification_str}.")
    except Exception as e:
        print(e)
        pass

    proof.set_enclave_quote_and_public_key(resp_json['quote'], resp_json['key'])

    # Generate a symmetric key
    symmetric_key = Fernet.generate_key()

    # Encrypt the symmetric key with enclave's pub key
    encrypted_key = encrypt_with_pub_key(symmetric_key, enclave_key)

    # 
    print_sep('UPLOAD CODE')
    encrypted_zip_bytes = zip_n_encrypt(code_path, symmetric_key)
    data = {}
    #data = { 'module': modulename, 'function': functionname}
    data['encrypted_key'] = bytes_to_base64_str(encrypted_key)
    data['encrypted_zip'] = bytes_to_base64_str(encrypted_zip_bytes)
    result = call_api(url, data, enclave_id, "code")

    dump_response(result)

    resp_json = result.json()
    encrypted_hashes = decode_if_base64(resp_json['encrypted_hashes'])
    file_hashes = json.loads(decrypt_fernet(encrypted_hashes, symmetric_key))
    print('     Filename              Hash')
    print('     ' + '-'*82)
    for k,v in file_hashes.items():
        print(f"     {k:<15}: {v}")
    
    proof.set_enclave_code_hash_and_signature(file_hashes, resp_json['signature'])
    
    # Encrypt the data with the symmetric key
    func_args = [int(3), int(4)]
    #encrypted_data = bytes_to_base64_str(encrypt_fernet(func_args.encode(), symmetric_key))
    
    print_sep('RUNNING FUNCTION')
    data = { 'module': modulename, 'function': functionname}
    data['encrypted_key'] = bytes_to_base64_str(encrypted_key)

    with open(params["data_filename"], "rb") as f:
        input_data = f.read()

    data['encrypted_data'] = bytes_to_base64_str(encrypt_fernet(input_data, symmetric_key))

    result = call_api(url, data, enclave_id, "run")
    dump_response(result)
    
    # Verify the signed result
    print_sep('VERIFYING RESULT')
    resp_json = result.json()
    #print(resp_json)
    func_result = resp_json['result']
    print(f"   result: {func_result}")
    signature = resp_json['signature']
    signature = b64_str_to_bytes(signature)
    if verify_with_pub_key(func_result.encode(), signature, enclave_key):
        verification_str = "succeeded [OK]"
    else:
        verification_str = "failed [ERROR]"
    print(f"[PraaS-Client] Signature verification {verification_str}.")

    enclave_output = json.loads(func_result)
    print("enclave_output: {}".format(enclave_output))
    proof.set_enclave_output_and_signature(enclave_output, resp_json['signature'])

    proof.dump_proof("proofs/proof_" + params["data_filename"].replace("/", "_") + ".json")

    # Finish
    print_sep('FINISH')
    #call_api(url, {}, enclave_id, "bye")
    url = f'{url}/{enclave_id}'
    response = requests.delete(url, json={})
    dump_response(response)
    return

def main():
    server_url = sys.argv[1]
    params = {}
    params["type"] = sys.argv[2]
    params["path"] = sys.argv[3]
    params['module'] = sys.argv[4]
    params['function'] = sys.argv[5]
    params['data_filename'] = sys.argv[6]
    
    os.makedirs("proofs", exist_ok=True)
    client_program(server_url, params)

if __name__ == '__main__':
    main()
