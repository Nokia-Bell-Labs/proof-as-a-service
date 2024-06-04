# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os
import sys
import io
import subprocess
import socket
import json
import base64
import zipfile
import uuid
import struct
#from threading import Thread
from functools import singledispatch, partial
print = partial(print, flush=True)
from flask import Flask, request, abort, make_response, jsonify

from dotenv import load_dotenv
import chardet
import re
from graminelibos import Manifest, get_tbssigstruct, sign_with_local_key, SGX_LIBPAL
import pickle
import importlib.util

import gramine_utils

# Load the enclave wrapper module 
MODULE_NAME = 'enclave'
MODULE_PATH = 'enclave/__init__.py'
spec = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
enclave_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enclave_module)

ENCLAVE_RUNTIMES = {
    "python": ""
}

API = enclave_module.API_TO_ECALL_MAP

# enclave_uuid -> (enclave_proc, ipc_conn)
active_enclave_map = {}

app = Flask(__name__)
entrypoint = '/sgx'

ipc_socket = None

@singledispatch
def stringify(arg) -> str:
    return arg

@stringify.register(str)
def _(arg):
    return arg

@stringify.register(bytes)
def _(arg):
    encoding = chardet.detect(arg)['encoding']
    if encoding in ("ascii", "utf-8"):
        return arg.decode()
    else:
        return base64.b64encode(arg).decode("utf-8")

# Convert bytes object to serializble string representation
def bytes_to_base64_str(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def is_base64(value) -> bool:
    RE_BASE64 = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
    return True if re.search(RE_BASE64, value) else False

def decode_base64(value):
    v = value.encode('utf-8')
    if len(v) % 4 != 0:
        return value
    try:
        decoded_value = base64.b64decode(v)
        return decoded_value
    except:
        return value

def decode_if_base64(value):
    try:
        decoded_value = base64.b64decode(value)
        return decoded_value
    except:
        # if an exception is raised during decoding, return the original value
        return value

def make_response_400(msg_txt, header_txt):
    print(f'[PraaS-Server] ERROR: {msg_txt}')
    response = make_response(msg_txt, 400)
    response.headers['X-Something'] = header_txt

def receive_message(socket):
    data_size = socket.recv(8)
    data_size = struct.unpack('<Q', data_size[0:8])[0]
    data = bytearray()

    while len(data) < data_size:
        buf = socket.recv(data_size - len(data))
        data.extend(buf)

    return pickle.loads(data)

def send_message(socket, msg):
    msg = pickle.dumps(msg)
    data_size_bytes = struct.pack('<Q', len(msg))
    socket.sendall(data_size_bytes)

    socket.sendall(msg)

def get_enclave_quote_and_key(socket) -> dict:
    data = {}
    # Get Quote from Enclave
    ipc_req = { 'cmd': 'quote', 'args': {} }
    send_message(socket, ipc_req)
    ipc_resp = receive_message(socket)
    if not ipc_resp['status'] == 'OK':
        raise Exception(f"Enclave response: {ipc_resp['text']}, {ipc_resp['status']}")
    data['quote'] = stringify(ipc_resp['data'])
    # Get PubKey from Enclave 
    ipc_req['cmd'] = 'key'
    send_message(socket, ipc_req)
    ipc_resp = receive_message(socket)
    if not ipc_resp['status'] == 'OK':
        raise Exception(f"Enclave response: {ipc_resp['text']}, {ipc_resp['status']}")
    data['key'] = stringify(ipc_resp['data'])
    return data

# Flask API server routes
#
@app.route(entrypoint, methods=['POST'])
# Expecting a multi-encoded post request
# Part 1: json data, name = 'json'
# Part 2: requirement file, name = 'pip'
# Part 3: zip file, name = 'zip'
def handle_request() -> str:
    if not request:
        abort(400)
    print(f'[PraaS-Server] New enclave request received ...')
    # Get the JSON data from the request
    request_data = json.loads(request.form['json'])

    try:
        if "type" not in request_data:
            # TODO: error handling
            #return make_response_400("Request contains no <Language> field.", 'Bad Request')
            return make_response("Request contains no <type> field.", 400)
        requested_type = request_data.get('type')
    except AttributeError as e:
        # Handle the case where the request data is not properly formatted
        #return make_response_400(f'Invalid JSON data. {e}', 'Invalid Request')
        return make_response(f'Invalid JSON data. {e}', 400)
    
    if requested_type not in ENCLAVE_RUNTIMES:
        # TODO: error handling
        #return make_response_400(f'Requested language <{requested_lang}> is not a valid option', 'Invalid Request')
        return make_response(f'Requested type <{requested_type}> is not a valid option', 400)
    else:
        enclave_lang = ENCLAVE_RUNTIMES[requested_type]
    
    # Assign new UUID to session
    client_uuid = uuid.uuid4()
    print(f"[PraaS-Server] Enclave ID: {client_uuid}")

    # Create work directory
    # If it already exists, remove all existing content in the work directory
    user_dir = os.path.join(os.path.abspath(os.getenv('WORK_DIR')), str(client_uuid))
    print(f"[PraaS-Server] Creating user dir: '{user_dir}'")
    if os.path.exists(user_dir):
        for item in os.listdir(user_dir):
            item_path = os.path.join(user_dir, item)
            if os.path.isdir(item_path):
                os.rmdir(item_path)
            else:
                os.remove(item_path)
    else:
        os.makedirs(user_dir, exist_ok=True)
 
    python_path_list = []
    # If request includes a requirements file  
    # pip install required modules in pip_package_dir
    if 'pip' in request.files:
        pip_flag = True
        pip_package_dir = os.path.join(user_dir, 'python-packages')
        try:
            os.makedirs(pip_package_dir)
        except:
            print(f"[PraaS-Server] ERROR: could not create '{pip_package_dir}'")
        initial_dir = os.getcwd()
        try: 
            req_file = request.files['pip']
            req_file_path = os.path.join(user_dir, 'requirements.txt')
            req_file.save(req_file_path)
            os.chdir(user_dir)
            print(f"[PraaS-Server] Installing modules in: '{pip_package_dir}'")
            subprocess.check_call(['pip', 'install', '-r', 'requirements.txt', '--target', pip_package_dir])
            python_path_list.append(pip_package_dir)
        except subprocess.CalledProcessError as e:
            print(f"[PraaS-Server] Module installation failed: {e}")
            return make_response_400('Bad requirements.txt', 'Invalid Request')
        finally:
            os.chdir(initial_dir)
    
    # If request includes a zip with user code
    # extract ZIP file to user_package_dir
    if 'zip' in request.files:
        zip_flag = True
        zip_file = request.files['zip']
        user_package_dir = os.path.join(user_dir, 'user-package')
        os.makedirs(user_package_dir)
        print(f"[PraaS-Server] Extracting ZIP to: '{user_package_dir}'")
        try:
            with zipfile.ZipFile(io.BytesIO(zip_file.read()), 'r') as zip_ref:
                zip_ref.extractall(user_package_dir)
            python_path_list.append(user_package_dir)
        except zipfile.BadZipFile as e:
            return make_response_400('Bad zipfile.', 'Invalid Request')

    # INET socket for IPC with the gramine enclave
    socket_info = ':'.join([str(v) for v in ipc_socket.getsockname()])
    
    # Generate the signed enclave app
    print(f"[PraaS-Server] Generating signed manifest:")
    gramine = gramine_utils.generate_gramine(enclave_id=client_uuid, 
                                                      work_dir=user_dir, 
                                                      python_path_list=python_path_list, 
                                                      socket_info=socket_info)
    # Start the enclave and wait for IPC message
    print(f"[PraaS-Server] Starting Enclave ...")
    enclave_proc = gramine_utils.start_enclave(work_dir=user_dir, app=gramine.appname)
    ipc_conn, ipc_addr = ipc_socket.accept()
    msg = receive_message(ipc_conn)
    if not msg['status'] == 'OK':
        print(f"[PraaS-Server] Enclave ERROR {msg['text']}")
        return make_response('Enclave failed', 'Server Error')
    ipc_req = { 'cmd': 'setid', 'id': str(client_uuid)}
    send_message(ipc_conn, ipc_req)
    ipc_resp = receive_message(ipc_conn)
    if not ipc_resp['status'] == 'OK':
        print(f"[PraaS-Server] Enclave ERROR {ipc_resp['text']}")
        return make_response('Enclave failed', 'Server Error')
    enclave_id = ipc_resp['enclave']
    print(f"[PraaS-Server] Enclave <{enclave_id}> ready.")
    active_enclave_map[enclave_id] = (enclave_proc, ipc_conn)
    
    response = {}
    response['id'] = str(client_uuid)
    response['type'] = 'python'
    # Get Quote and PubKey from Enclave
    quote_key = get_enclave_quote_and_key(ipc_conn)
    response = {**response, **quote_key}
    return jsonify(response)

@app.route(f'{entrypoint}/<string:enclave_uuid>', methods=['GET'])
def handle_get_enclave_info(enclave_uuid):
    if enclave_uuid not in active_enclave_map:
        print(f'[PraaS Server] ERROR: enclave <{enclave_uuid}> does not exist.')
        response = make_response(f"Invalid enclave id.", 400)
        response.headers['X-Something'] = 'Invalid Request'
        return response
    proc, ipc_conn = active_enclave_map[enclave_uuid]
    response = {}
    response['id'] = enclave_uuid
    response['type'] = 'python'
    # Get Quote and PubKey from Enclave
    quote_key = get_enclave_quote_and_key(ipc_conn)
    response = {**response, **quote_key}
    return jsonify(response)

@app.route(f'{entrypoint}/<string:enclave_uuid>/code', methods=['POST'])
def handle_upload_request(enclave_uuid):
    if enclave_uuid not in active_enclave_map:
        print(f'[PraaS Server] ERROR: enclave <{enclave_uuid}> does not exist.')
        response = make_response(f"Invalid enclave id.", 400)
        response.headers['X-Something'] = 'Invalid Request'
        return response
    proc, ipc_conn = active_enclave_map[enclave_uuid]
    
    data = request.get_json()
    for k, v in data.items():
        if k in ['encrypted_key', 'encrypted_zip']:
            data[k] = decode_base64(v)
    ipc_req = { 'cmd': 'code', 'args': data }
    send_message(ipc_conn, ipc_req)
    ipc_resp = receive_message(ipc_conn)
    if ipc_resp['status'] == 'ERROR':
        response = make_response(f"{ipc_resp['text']}", 400)
    else:
        response = {}
        response['id'] = enclave_uuid
        response['type'] = 'python'
        response['encrypted_hashes'] = bytes_to_base64_str(ipc_resp['data'])
        response['signature'] = bytes_to_base64_str(ipc_resp['signature'])
        response = jsonify(response)
    return response

@app.route(f'{entrypoint}/<string:enclave_uuid>/run', methods=['POST'])
def handle_run_request(enclave_uuid):
    if enclave_uuid not in active_enclave_map:
        print(f'[PraaS Server] ERROR: enclave <{enclave_uuid}> does not exist.')
        response = make_response(f"Invalid enclave id.", 400)
        response.headers['X-Something'] = 'Invalid Request'
        return response
    proc, ipc_conn = active_enclave_map[enclave_uuid]
    
    data = request.get_json()
    for k, v in data.items():
        if k in ['encrypted_key', 'encrypted_data']:
            data[k] = decode_base64(v)
    
    ipc_req = { 'cmd': 'run', 'args': data }
    send_message(ipc_conn, ipc_req)
    ipc_resp = receive_message(ipc_conn)
    if ipc_resp['status'] == 'ERROR':
        response = make_response(f"{ipc_resp['text']}", 400)
    else:
        response = {}
        response['id'] = enclave_uuid
        response['type'] = 'python'
        response['result'] = stringify(ipc_resp['data'])
        response['signature'] = stringify(ipc_resp['signature'])
        response = jsonify(response)
    return response

@app.route(f'{entrypoint}/<string:enclave_uuid>', methods=['DELETE'])
def del_enclave(enclave_uuid):
    if not request:
        abort(400)
    print(f'[PraaS-Server] Received request to shutdown Enclave {enclave_uuid}')
    if enclave_uuid not in active_enclave_map:
        print(f'[PraaS Server] ERROR: enclave <{enclave_uuid}> does not exist.')
        response = make_response(f"Invalid enclave id.", 400)
        response.headers['X-Something'] = 'Invalid Request'
        return response
    proc, ipc_conn = active_enclave_map[enclave_uuid]
    ipc_req = { 'cmd': 'bye', 'args': request.get_json() }
    send_message(ipc_conn, ipc_req)
    ipc_resp = receive_message(ipc_conn)
    if not ipc_resp['status'] == 'BYE':
        print(f"[PraaS-Server] Enclave shutdown error.")
        return make_response('Enclave shutdown failed', 'Server Error')
    try:
        ipc_conn.close()
    except:
        pass
    del active_enclave_map[enclave_uuid]
    response = {}
    response['id'] = enclave_uuid
    response['status'] = 'BYE'
    return jsonify(response)
        
def main():
    load_dotenv()
    host = os.getenv('HOST')
    port = os.getenv('PORT')
    ipc_port = os.getenv('IPC_PORT')
    app.config['WORK_DIR'] = os.getenv('WORK_DIR')
    app.config['GRAMINE_TEMPLATE'] = os.getenv('GRAMINE_TEMPLATE')

    # Sanity check the variables
    if not host or not port:
        raise ValueError('Host and/or port are not set in environment variables') 
    if not ipc_port:
        raise ValueError('IPC port is not set in environment variables') 
    # Check that all keys are present in os.environ and have values
    required_params = ['WORK_DIR', 'GRAMINE_TEMPLATE']
    missing_keys = [key for key in required_params if key not in os.environ]
    if missing_keys:
        raise ValueError(f'Missing configuration keys: {missing_keys}')
    missing_values = [key for key in required_params if not os.environ.get(key)]
    if missing_values:
        raise ValueError(f'Missing values for configuration keys: {missing_values}')
    missing_files = [key for key in required_params if not os.path.exists(os.environ.get(key))]
    if missing_files:
        raise ValueError(f'Missing files for configuration keys: {missing_files}')
    
    # Serve request forever
    try:
        # Start the Flask server
        print('*'*50)
        print(f'[PraaS-Server] Starting server on <{host}:{port}>')
        print('*'*50)
        global ipc_socket
        print(f'[PraaS-Server] Starting IPC server <{host}:{ipc_port}>')
        ipc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ipc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ipc_socket.bind((host, int(ipc_port)))
        ipc_socket.listen()
        app.run(threaded=True, debug=False, port=port)
        ipc_socket.close()
    except KeyboardInterrupt:
        print(f"[PraaS-Server] CLEANING UP")
        ipc_socket.close()
        pass

    print(f'[PraaS-Server] Closed.')

if __name__ == '__main__':
    main()
