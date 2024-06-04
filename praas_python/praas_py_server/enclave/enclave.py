# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import sys
import os
import io
import json
import zipfile
import re
import importlib
import importlib.util
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Import all modules in a directory and subdirectories 
def import_usermodules_from_dir(modules_dir='/userdir/python-packages', prefix='usermodules'):
    dirPath = next(os.walk(modules_dir))[0]
    # Load functions from uploaded user files
    modules_dir = os.path.abspath(modules_dir)
    sys.path.insert(0, modules_dir)
    for dirpath, dirnames, filenames in os.walk(modules_dir):
        # Ignore subdirectories that start with underscore.
        dirnames[:] = [d for d in dirnames if not d.startswith('_')]
        for filename in filenames:
            # Skip non-Python files and __init__.py
            if not filename.endswith('.py') or filename == '__init__.py':
                continue
            # Import the module.
            modname = os.path.splitext(filename)[0]
            relpath = os.path.relpath(dirpath, modules_dir)
            if relpath == '.':
                relpath = ''
                modpath = modname
            else:    
                modpath = '.'.join([relpath.replace('/', '.'), modname])
            __import__(modpath)
    sys.path.pop(0)

def transform_to_path(name_string):
    # Transform a string of names separated by "." into a filesystem path.
    return os.path.join(*name_string.split("."))

# Function to decrypt symmetric key using RSA private key
def decrypt_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Function to encrypt data
# Only Fernet recipe
def _fernet_encrypt_data(data: str, key) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())

def encrypt_data_str(data: str, key) -> bytes:
    return _fernet_encrypt_data(data, key)

# Function to decrypt data 
# Only Fernet recipe
def _fernet_decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data)

def decrypt_data(encrypted_data, key):
    return _fernet_decrypt_data(encrypted_data, key)

class Enclave:
    def __init__(self, id=None):
        # Initialize the enclave
        # The path to the tmps in-memory file
        self.tmp_path = f'/tmp'
        sys.path.append(self.tmp_path)
        self._id = id
        self._init_key_pair()
        self.user_module = None
        self.user_function = None

    def _init_key_pair(self):
        # Generate a new RSA key pair
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self._public_key = self._private_key.public_key()
        # Write the secure hash of the key into the user_report_data
        hash_object = hashes.Hash(hashes.SHA256())
        hash_object.update(self.public_key)
        try:       
            with open("/dev/attestation/user_report_data", "wb") as f:
                f.write(hash_object.finalize())
        except FileNotFoundError:
            print(f'Enclave: Cannot find `/dev/attestation/user_report_data`; '
                  "are you running with SGX enabled?")

    @property
    def id(self) -> str:
        return self._id
    
    @id.setter
    def id(self, id_str) -> str:
        # Protection: initialize only once
        # Subsequent tries will return existing id
        if self._id is None: 
            self._id = id_str
        return self._id

    @property
    def public_key(self) -> bytes:
        # Serialize the public key
        serialized_public_key = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Return the public key
        return serialized_public_key

    @property
    def quote(self) -> bytes:
        if not os.path.exists("/dev/attestation/quote"):
            # TODO: throw an exception rather than just returning an empty bytes object
            print(f'Enclave: Cannot find `/dev/attestation/quote`; '
                'are you running with remote attestation enabled?')
            return bytes()
        with open ('/dev/attestation/attestation_type') as f:
            self.attestation_type = f.read()
        with open("/dev/attestation/quote", "rb") as f:
            quote = f.read()
        return quote

    def _extract_module_name_and_function_name_from_script(self, file_path):
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{file_path} does not exist")

        # Read the file contents
        with open(file_path, 'r') as f:
            contents = f.read()

        # Use regex to check for the import statement
        match = re.search(r'from \.(\w+) import (\w+)', contents)

        if not match:
            raise ImportError("No import statement found.")

        # Extract module and function names from the regex match object
        module_name = match.group(1)
        function_name = match.group(2)
        return module_name, function_name

    def _import_module_and_function(self, module_name: str, function_name: str) -> str:
        # Import and load the module dynamically
        sys.path.insert(0, self.tmp_path)
        try:
            #module = importlib.import_module('.' + module_name, package=None)
            module = importlib.import_module(module_name)
            user_function = getattr(module, function_name)
        except Exception as e:
            raise ImportError(f"Error loading module: {e}")
        # Set the loaded module and function as object properties
        self.user_module = module
        self.user_function = user_function
        sys.path.pop(0)
        return f'{module_name}.{function_name}'
    
    def ecall_load_function(self, encrypted_zip, encrypted_key, **kwargs) -> str:
        # Decrypt the symmetric key with the enclave's private key
        key = decrypt_key(encrypted_key, self._private_key)
        # Decrypt the zip file
        decrypted_zip = decrypt_data(encrypted_zip, key)

        # Extract the zip file to the target directory
        with zipfile.ZipFile(io.BytesIO(decrypted_zip), 'r') as zip_ref:
            zip_ref.extractall(self.tmp_path)
       
        # Hash every file in the target directory
        file_hashes = {}
        for root, dirs, files in os.walk(self.tmp_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, 'rb') as f:
                    file_bytes = f.read()
                file_hash = hashes.Hash(hashes.SHA256())
                file_hash.update(file_bytes)
                file_digest = file_hash.finalize()
                file_hashes[file] = file_digest.hex()

        # Load the client-submitted code dynamically
        #
        # Option 1: module and function name are specified as args
        module_file_path = ''
        if ('module' in kwargs) and ('function' in kwargs):
            module_name = decrypt_data(kwargs['module'], key).decode()
            function_name = decrypt_data(kwargs['function'], key).decode()
            module_file_path = f'{self.tmp_path}/{transform_to_path(module_name)}.py'
        # Option 2: User submitted zip includes a '__init__.py' file with an import statement
        #           'from .{modulename} import {functionname} as do_compute
        else:
            module_file_path = f'{self.tmp_path}/__init__.py'
            print(f'Enclave: ecall_load_function: extracting module_file_path from {module_file_path}')
            try:
                module_name, function_name = self._extract_module_name_and_function_name_from_script(module_file_path)
            except Exception as e:
                print(f'Enclave: ecall_load_function: ERROR: {e}')
                return None
        print(f'Enclave: ecall_load_function: module_path   = {module_file_path}')
        print(f'Enclave: ecall_load_function: module_name   = {module_name}')
        print(f'Enclave: ecall_load_function: function_name = {function_name}')
        try:
            result = self._import_module_and_function(module_name, function_name)
        except Exception as e:
            print(f'Enclave: ERROR: {e}')
            return None
        file_hashes_json = json.dumps(file_hashes, sort_keys=True)
        encrypted_file_hashes = encrypt_data_str(file_hashes_json, key)
        signature = sign_data(file_hashes_json.encode(), self._private_key)
        return encrypted_file_hashes, signature
    
    def ecall_run(self, encrypted_data, encrypted_key, **kwargs):
        print(f'Enclave: ecall_run')
        result = None
        # Decrypt the symmetric key with the enclave's private key
        key = decrypt_key(encrypted_key, self._private_key)

        # Decrypt the data
        decrypted_data = decrypt_data(encrypted_data, key)
        try:
            # Try to decode the byte string as ASCII-encoded characters
            decoded_string = decrypted_data.decode('ascii')
            decrypted_data = decoded_string
        except:
            pass
        
        # Execute the client function with the decrypted client data
        if 'module' in kwargs and 'function' in kwargs:
            #print(f"   invoking {kwargs['module']}.{kwargs['function']}")
            try:
                usermodule = importlib.import_module(kwargs['module'])
            except:
                raise Exception(f"ecall_run: failed importing module '{kwargs['module']}'.")
            #if not kwargs['module'] in sys.modules:
            #    raise Exception(f"ecall_run: invalid module '{kwargs['module']}'.")
            #usermodule = sys.modules[kwargs['module']]
            if not kwargs['function'] in dir(usermodule):
                raise Exception(f"ecall_run: invalid function '{kwargs['function']}'.")
            func = getattr(usermodule, kwargs['function'])
        else:
            func = self.user_function
            if not func:
                raise Exception(f"ecall_run error: no user function specified: {e}")
        try:
            result = func(decrypted_data)
        except Exception as e:
            raise Exception(f"ecall_run error: {func.__name__}: {e}")
        signature = sign_data(result.encode(), self._private_key)
        return result, signature
    
    def ecall_clean_up(self) -> str:
        print(f'Enclave: ecall_clean_up')
        return f'Enclave {self._id}] BYE.'
