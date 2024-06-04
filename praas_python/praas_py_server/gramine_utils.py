# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os
import datetime
from functools import singledispatch, partial
print = partial(print, flush=True)
from graminelibos import Manifest, get_tbssigstruct, sign_with_local_key, SGX_LIBPAL
import subprocess

import importlib.util

# Load the enclave wrapper module 
MODULE_NAME = 'enclave'
MODULE_PATH = 'enclave/__init__.py'
spec = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
enclave_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enclave_module)

SUPPORTED_ATTESTATION_TYPES = ['dcap']

class Gramine():
    def __init__(self, 
                 manifest:str = None, 
                 sgxfile:str = None,
                 sigfile:str = None,
                 appname:str = None
                 ):
        self.manifest = manifest
        self.sgxfile = sgxfile
        self.sigfile = sigfile
        self.appname = appname

def gramine_is_valid_ra_type(ra_type: str) -> bool:
    if ra_type in SUPPORTED_ATTESTATION_TYPES:
        return True
    else:
        raise ValueError(f"Invalid RA_TYPE '{ra_type}'. Allowed  ")

# Internal helper funtion to create the Gramine manifest from a template
# adding all files of the enclave wrapper code to the sgx.trusted_files
# and the socket to the sgx.allowed_files context
# Return: manifest object, manifest filepath
def _gramine_manifest(enclave_id: str, work_dir: str, python_path_list, socket_info: str):
    # Generate the manifest from the template and adding specifics for this enclave
    template_path = os.path.abspath(os.getenv('GRAMINE_TEMPLATE'))
    # General manifest params 
    manifest_vars = {
        'arch_libdir': os.getenv('ARCH_LIBDIR'),
        'entrypoint': os.getenv('PYTHON_PATH'),
        'log_level': os.getenv('ENCLAVE_LOG_LEVEL'),
        'ra_type': os.getenv('ENCLAVE_RA_TYPE'),
        'ra_client_spid': os.getenv('ENCLAVE_RA_CLIENT_SPID'),
        'ra_client_linkable': os.getenv('ENCLAVE_RA_CLIENT_LINKABLE')
    }

    ipc_type = 'socket'
    # Specific params 
    app_dir = os.path.dirname(os.path.abspath(enclave_module.__file__))
    manifest_vars['app_dir'] = app_dir
    # Main script and arguments it expects
    entrypoint_script = enclave_module.START_SCRIPT
    #entrypoint_script = 'enclave/enclave.py'
    manifest_vars['loader_args'] = [
        entrypoint_script,
        #enclave_id,
        'enclave_id',
        ipc_type,
        socket_info
    ]
    
    #env_pythonpath = ""
    python_relpaths = []
    print(python_path_list)
    for path in python_path_list:
        relpath = os.path.relpath(path, work_dir) + '/'
        python_relpaths.append(relpath)
        #env_pythonpath = env_pythonpath + ':' + '/userdir/' + relpath
    manifest_vars['python_relpaths'] = python_relpaths
    manifest_vars['work_dir'] = work_dir
    #manifest_vars['pythonpath'] = env_pythonpath
    
    with open(template_path, 'r') as f:
        template_string = f.read()
    manifest = Manifest.from_template(template_string, manifest_vars)

    # Add main python script and other necessary files to the sgx trusted files [r]  
    app_files = [ os.path.join(app_dir, file) for file in  enclave_module.MODULE_FILES ]
    manifest['sgx']['trusted_files'].extend([{'uri': f'file:{file}'} for file in app_files])
    manifest

    base_filename, file_extension = os.path.splitext(os.path.basename(template_path))
    manifest_path = os.path.join(work_dir, base_filename)
    with open(manifest_path, 'wb') as f:
        manifest.dump(f)
    return manifest, manifest_path

# Internal helper function
# Expand the sgx trusted files and # generate signatures 
# for the manifest file and the libpal file (main Gramine binary)
# Return: path to '<app>.manifest.sgx', path to '<app>.sig'
def _gramine_sgx_sign(manifest, manifest_path):
    signing_key = os.getenv('SGX_RSA_KEY_PATH')
    if not os.path.exists(signing_key):
        raise FileNotFoundError(f"Signing key'{signing_key}' does not exist.")
    manifest_sgx = manifest_path + '.sgx'

    expanded = manifest.expand_all_trusted_files()
    
    with open(manifest_sgx, 'wb') as f:
        manifest.dump(f)

    if manifest_path.endswith('.manifest'):
        sigfile = manifest_path[:-len('.manifest')]
    else:
        sigfile = manifest_path
    sigfile += '.sig'

    today = datetime.date.today()
    sigstruct = get_tbssigstruct(manifest_sgx, today, SGX_LIBPAL, verbose=False)
    sigstruct.sign(sign_with_local_key, signing_key)

    with open(sigfile, 'wb') as f:
        f.write(sigstruct.to_bytes())
    return manifest_sgx, sigfile

# Main function to be invoked to generate the Gramine app
# Return the app name to be passed to gramine-sgx
# Only support Socket IPC channel. 
def generate_gramine(enclave_id:str=None, work_dir:str=None, python_path_list=None, socket_info:str=None) -> str:
    if not work_dir:
        raise FileNotFoundError(f"User directory is not specified.")
    else:
        work_dir = os.path.abspath(work_dir)
    if not os.path.exists(work_dir):
        raise FileNotFoundError(f"User directory '{work_dir}' does not exist.")

    manifest, manifest_path = _gramine_manifest(enclave_id, work_dir, python_path_list, socket_info)
    manifest_sgx, enclave_sig = _gramine_sgx_sign(manifest, manifest_path)
    gramine_app, extension = os.path.splitext(enclave_sig)
    print(f"  Manifest:     {manifest_path}")
    print(f"  SGX manifest: {manifest_sgx}")
    print(f"  SIG file:     {enclave_sig}")
    print(f"  Gramine app:  {gramine_app}")
    
    gramine = Gramine(manifest=manifest_path, sgxfile=manifest_sgx, sigfile=enclave_sig, appname=gramine_app)
    return gramine

# Start a new enclave process
def start_enclave(work_dir:str=None, app:str=None) -> subprocess.Popen:
    cmd = ['gramine-sgx', app]
    stdout_file = os.path.join(work_dir, 'stdout_stderr.txt')
    with open(stdout_file, "w") as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=f)
    return proc

