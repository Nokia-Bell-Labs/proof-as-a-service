# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import base64
import json
import sys

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

ATTESTATION_SERVICE_URL = None

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
    except Exception as exc:
        raise
        return False

def b64_str_to_bytes(b64_str) -> bytes:
    #return base64.decodebytes(str_base64.encode('utf-8'))
    return base64.b64decode(b64_str)

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

def check_proof(proof_filename):
    global ATTESTATION_SERVICE_URL
    with open(proof_filename, "r") as f:
        proof_json = f.read()
        proof = json.loads(proof_json)


    ATTESTATION_SERVICE_URL = proof["attestation_service_url"]
    quote = proof["enclave_quote"]

    quote = b64_str_to_bytes(proof["enclave_quote"])
    dump_quote(quote)
    enclave_key = bytes(proof["enclave_public_key"], "utf-8")
    try:
        verify_quote(quote, enclave_key)
        print("SUCCESSFULLY VERIFIED QUOTE")
    except Exception as exc:
        raise
    
    # Verify the enclave's public key
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

    # Verify the signed result
    print('VERIFYING RESULT')

    func_result = json.dumps(proof["enclave_output"])
    print(f"   result: {func_result}")
    signature = proof["enclave_signature"]
    signature = b64_str_to_bytes(signature)
    if verify_with_pub_key(bytes(func_result, "utf-8"), signature, enclave_key):
        verification_str = "succeeded [OK]"
    else:
        verification_str = "failed [ERROR]"
    print(f"[PraaS-Client] Signature verification {verification_str}.")
    

if __name__ == '__main__':
    proof_filename = sys.argv[1]
    check_proof(proof_filename)