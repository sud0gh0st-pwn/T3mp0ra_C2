#!/usr/bin/env python3
"""
Tempora C2 Frontend API Client
This module provides a socket-based client for communicating with the C2 server.
"""

import socket
import json
import logging
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
import os
import threading

class C2APIClient:
    def __init__(self, server_host='127.0.0.1', server_port=5000):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.connected = False
        self.client_id = None
        self.symmetric_key = None
        self.hmac_key = None
        self.cipher_suite = None
        self.socket_lock = threading.Lock()
        self.key_lock = threading.Lock()
        
        # Setup logging
        self.logger = logging.getLogger("tempora-api-client")
        
    def connect(self):
        """Connect to the C2 server and perform key exchange"""
        self.logger.info(f"Attempting to connect to server at {self.server_host}:{self.server_port}")
        return self._connect()
    
    def _connect(self):
        """Internal method to establish connection with server"""
        self.connected = False
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(120)
            self.socket.connect((self.server_host, self.server_port))
            self.logger.info("Connected to server")
            
            # Wait for server's READY_FOR_KEY_EXCHANGE
            server_ready = self.socket.recv(1024)
            if server_ready != b'READY_FOR_KEY_EXCHANGE':
                raise ValueError("Server not ready for key exchange")

            # Send CLIENT_READY after server preamble
            self.socket.sendall(b'CLIENT_READY')
            
            # Receive server's public key
            server_public_key_pem = self.socket.recv(2048)
            server_public_key = serialization.load_pem_public_key(server_public_key_pem)
            
            # Generate and encrypt keys
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
            
            # Send key lengths first
            self.socket.sendall(f"{len(encrypted_symmetric_key):010d}".encode())
            self.socket.sendall(f"{len(encrypted_hmac_key):010d}".encode())
            
            # Send encrypted keys
            self.socket.sendall(encrypted_symmetric_key)
            self.socket.sendall(encrypted_hmac_key)
            
            # Wait for key exchange completion
            exchange_result = self.socket.recv(1024)
            if exchange_result != b'KEY_EXCHANGE_COMPLETE':
                raise ValueError("Key exchange failed")

            # Receive client id if provided
            try:
                client_id_len_raw = self.socket.recv(4)
                if len(client_id_len_raw) == 4:
                    client_id_len = int.from_bytes(client_id_len_raw, "big")
                    client_id_bytes = self.socket.recv(client_id_len)
                    if len(client_id_bytes) == client_id_len:
                        self.client_id = client_id_bytes.decode()
                        self.logger.info(f"Assigned client id: {self.client_id}")
            except Exception:
                self.client_id = None
            
            self.logger.info("Successful key exchange")
            self.connected = True
            return True
            
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            self.cleanup()
            return False
    
    def send_request(self, request_type, data=None):
        """Send an encrypted request to the server and get the response"""
        if not self.connected:
            if not self.connect():
                return None
        
        try:
            with self.socket_lock:
                request = {
                    'type': request_type,
                    'data': data,
                    'timestamp': time.time()
                }
                
                encrypted_request = self.cipher_suite.encrypt(
                    json.dumps(request).encode()
                )
                h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                h.update(encrypted_request)
                request_hmac = h.finalize()
                
                data_length = len(encrypted_request).to_bytes(4, 'big')
                self.socket.sendall(data_length)
                self.socket.sendall(encrypted_request)
                self.socket.sendall(request_hmac)
                
                # Wait for response
                length_bytes = self.socket.recv(4)
                if len(length_bytes) != 4:
                    return None
                data_length = int.from_bytes(length_bytes, 'big')
                
                encrypted_response = b''
                while len(encrypted_response) < data_length:
                    chunk = self.socket.recv(data_length - len(encrypted_response))
                    if not chunk:
                        break
                    encrypted_response += chunk
                
                if len(encrypted_response) != data_length:
                    return None
                
                response_hmac = self.socket.recv(32)
                if len(response_hmac) != 32:
                    return None
                
                h = hmac.HMAC(self.hmac_key, hashes.SHA256())
                h.update(encrypted_response)
                try:
                    h.verify(response_hmac)
                except Exception:
                    return None
                
                response = json.loads(self.cipher_suite.decrypt(encrypted_response).decode())
                return response
                
        except Exception as e:
            self.logger.error(f"Request error: {e}")
            self.cleanup()
            return None
    
    def cleanup(self):
        """Clean up resources"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.socket = None
        self.connected = False
        self.symmetric_key = None
        self.hmac_key = None
        self.cipher_suite = None
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup() 
