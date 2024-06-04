# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import socket
import pickle
import base64
import struct

from enclave import Enclave

IPC = [
    'socket',
    'unix_socket',
    'pipe',
    'shared_memory'
]

API_TO_ECALL_MAP = {
    "quote": "quote",
    "key": "public_key",
    "code": "ecall_load_function",
    "run": "ecall_run",
    "bye": "ecall_clean_up"
}

def decode_if_base64(value):
    try:
        '''
        # check if the value is a valid base64 string
        if isinstance(value, str) and len(value) % 4 == 0:
            decoded_value = base64.b64decode(value.encode('utf-8'))
            return decoded_value
        else:
            print(f'{value} IS NOT base64')
            # if the value is not a base64 string, return it as-is
            return value
        '''
        decoded_value = base64.b64decode(value)
        return decoded_value
    except:
        # if an exception is raised during decoding, return the original value
        return value

#######################################
# Inter Process Communication classes #
#######################################

class IPC:
    def __init__(self, name=None):
        if name:
            self.name = name
        else:
            self.name = 'IPC'
        print(f"{self.name}: initialized.")
        pass 
    
    def receive_message(self) -> str:
        raise NotImplementedError

    def send_message(self, message) -> str:
        raise NotImplementedError

    def close(self):
        print(f"{self.name}: closed.")

class SocketIPC(IPC):
    def __init__(self, socket_info):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_info = socket_info.split(':')
        socket_addr  = (socket_info[0], int(socket_info[1]))
        self.socket.connect(socket_addr)
        super().__init__(f"SocketIPC {socket_addr}")

    def receive_message(self):
        data_size = self.socket.recv(8)
        data_size = struct.unpack('<Q', data_size[0:8])[0]

        data = bytearray()

        while len(data) < data_size:
            buf = self.socket.recv(data_size - len(data))
            data.extend(buf)

        return pickle.loads(data)

    def send_message(self, message):
        msg = pickle.dumps(message)

        data_size_bytes = struct.pack('<Q', len(msg))
        self.socket.sendall(data_size_bytes)

        self.socket.sendall(msg)

    def close(self):
        self.socket.shutdown(socket.SHUT_WR)
        self.socket.close()
        super().close()

class UnixSocketIPC(IPC):
    def __init__(self, unix_socket_info):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(unix_socket_info)

    def receive_message(self):
        message = b''
        while True:
            chunk = self.socket.recv(1024)
            message += chunk
            if len(chunk) < 1024:
                break
        return pickle.loads(message)

    def send_message(self, message):
        self.socket.sendall(pickle.dumps(message))
        
    def close(self):
        self.socket.close()

class PipeIPC(IPC):
    def __init__(self, pipe_info):
        self.pipe = pipe_info

    def receive_message(self):
        return self.pipe.recv()

    def send_message(self, message):
        self.pipe.send(message)

class SharedMemoryIPC(IPC):
    def __init__(self, shared_memory_info):
        self.mem = shared_memory_info

    def receive_message(self):
        return pickle.loads(self.mem.value)

    def send_message(self, message):
        self.mem.value = pickle.dumps(message)


#######################################
# Dispatcher base and derived classes #
#######################################

#class Dispatcher(threading.Thread):
class Dispatcher():
    def __init__(self, enclave: Enclave, ipc: str, name: str = None):
        #super().__init__() # if inheriting from threading.Thread
        self.enclave = enclave
        self.ipc = ipc
        if name:
            self.name = name
        else:
            self.name = 'Dispatcher'
        print(f"{self.name}: initialized.")

    def decode_message(self, message):
        decoded_message = message.copy()
        if 'data' in message:
            for k, v in message['data'].items():
                decoded_message['data'][k] = decode_if_base64(v)
        return decoded_message

    def run(self):
        # Notify parent process that child process has successfully initialized
        msg = {
            'enclave': None,
            'status': 'OK',
            'message': f'{self.name} ready to receive Id.'
        }
        self.ipc.send_message(msg)
        
        print(f"[Dispatcher] Waiting for Id assignment ...", flush=True)
        id_message = self.ipc.receive_message()
        if id_message['cmd'] != 'setid':
            msg['status'] = 'ERROR'
            msg['message'] = 'Need to set Enclave Id first.'
        else:
            self.enclave.id = id_message['id']
            msg['enclave'] = self.enclave.id
        print(f"[Dispatcher] Id <{self.enclave.id}> assigned", flush=True)
        self.ipc.send_message(msg)
        
        ecall_functions = set([name for name, value in vars(Enclave).items() if not name.startswith('_')])
        ecall_properties = set([name for name, value in vars(Enclave).items() if isinstance(value, property)])

        # Wait for subsequent request messages from parent process
        while True:
            message = self.ipc.receive_message()
            ipc_resp = {
                'status': '',
                'text': '',
                'data': None,
                'signature': None
            }
            # Decode message if necessary
            message = self.decode_message(message)
            #print(f"ipc_req;  {message}", flush=True)
            # Extract command string from message
            cmd_str = message['cmd']
            # Check if command is supported
            if cmd_str not in API_TO_ECALL_MAP:
                ipc_resp['status'] = 'ERROR'
                ipc_resp['text'] = f'Unsupported command: {cmd_str}'
                self.ipc.send_message(ipc_resp)
                continue
            ecall_str = API_TO_ECALL_MAP[cmd_str]
            ecall = getattr(self.enclave, API_TO_ECALL_MAP[cmd_str])
            if cmd_str == 'bye':
                result = ecall()
                break
            # Extract data from message and call corresponding method on Enclave object
            if ecall_str in ecall_properties:
                result = ecall
                ipc_resp['status'] = 'OK'
                ipc_resp['data'] = result
            elif ecall_str in ecall_functions:
                kwargs = message['args']
                try:
                    result, signature = ecall(**kwargs)
                    ipc_resp['status'] = 'OK'
                    ipc_resp['data'] = result
                    ipc_resp['signature'] = signature
                except Exception as e:
                    print(ecall_str)
                    ipc_resp['status'] = 'ERROR'
                    ipc_resp['text'] = str(e)
            #print(f"ipc_resp: {ipc_resp}", flush=True)
            self.ipc.send_message(ipc_resp)
        self.close()
    
    def close(self):
        self.ipc.send_message({'status': 'BYE', 'message': f'Cleaning up.'})
        print(f"{self.name}: finished.")
        #self.ipc.close()

class SocketDispatcher(Dispatcher):
    def __init__(self, enclave, socket_info):
        ipc = SocketIPC(socket_info)
        super().__init__(enclave, ipc, 'SocketDispatcher')

class UnixSocketDispatcher(Dispatcher):
    def __init__(self, enclave, unix_socket_info):
        ipc = UnixSocketIPC(unix_socket_info)
        super().__init__(enclave, ipc)

class PipeDispatcher(Dispatcher):
    def __init__(self, enclave, pipe_info):
        ipc = PipeIPC(pipe_info)
        super().__init__(enclave, ipc, 'PipeDispatcher')

class SharedMemoryDispatcher(Dispatcher):
    def __init__(self, enclave, shared_memory_info):
        ipc = SharedMemoryIPC(shared_memory_info)
        super().__init__(enclave, ipc)


class DispatcherFactory:
    @staticmethod
    def create_dispatcher(ipc_type, ipc_info, enclave):
        print(f"Creating Dispatcher: {ipc_type} '{ipc_info}'")
        if ipc_type == 'pipe':
            return PipeDispatcher(enclave, ipc_info)
        elif ipc_type == 'socket':
            return SocketDispatcher(enclave, ipc_info)
        elif ipc_type == 'unix_socket':
            return UnixSocketDispatcher(enclave, ipc_info)
        elif ipc_type == 'shared_memory':
            return SharedMemoryDispatcher(enclave, ipc_info)
        else:
            raise ValueError(f'Invalid IPC type: {ipc_type}')
