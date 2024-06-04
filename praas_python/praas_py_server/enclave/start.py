# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# For relative imports to work in Python 3.6
import os, sys; sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from enclave import Enclave
from dispatcher import DispatcherFactory

import sys

enclave_singleton = None

#def run(enclave_id: str, ipc_type: str, ipc_info: str):
def run(ipc_type: str, ipc_info: str):
    # Create the enclave object
    global enclave_singleton
    enclave_id = 'Id pending'
    print(f"[Gramine] START: {enclave_id}")
    #enclave_singleton = Enclave(enclave_id)
    enclave_singleton = Enclave()
    dispatcher = DispatcherFactory.create_dispatcher(ipc_type, ipc_info, enclave_singleton)
    dispatcher.run()
    print(f"[Gramine] BYE: {enclave_singleton.id}") 

if __name__ == '__main__':
    #enclave_id = sys.argv[1]
    ipc_type = sys.argv[2] 
    ipc_info = sys.argv[3]
    #run(enclave_id, ipc_type, ipc_info)
    run(ipc_type, ipc_info)
