import unittest
import socket
import threading
import time
import json
import sys
import os
import io
from unittest.mock import patch, MagicMock, call
from queue import Queue
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac

# Add parent directory to path to import server and client modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server import C2Server
from client import C2Client

class MockSocket:
    """Mock socket for testing client-server communication"""
    def __init__(self):
        self.sent_data = []
        self.recv_queue = Queue()
        self.closed = False
    
    def sendall(self, data):
        self.sent_data.append(data)
    
    def recv(self, bufsize):
        try:
            return self.recv_queue.get(block=False)
        except:
            return b''
    
    def close(self):
        self.closed = True
    
    def queue_recv_data(self, data):
        self.recv_queue.put(data)

class TestClientResponses(unittest.TestCase):
    """Test client responses to server commands"""
    
    def setUp(self):
        """Set up test environment"""
        # Patch the logging setup to avoid file handler issues
        self.logging_patcher = patch('logging.FileHandler')
        self.mock_file_handler = self.logging_patcher.start()
        self.mock_file_handler.return_value = MagicMock()
        
        # Mock socket connections
        self.server_socket = MockSocket()
        self.client_socket = MockSocket()
        
        # Create test keys
        self.test_symmetric_key = Fernet.generate_key()
        self.test_hmac_key = os.urandom(32)
        self.cipher_suite = Fernet(self.test_symmetric_key)
        
        # Patch socket creation
        self.socket_patcher = patch('socket.socket')
        self.mock_socket_class = self.socket_patcher.start()
        self.mock_socket_class.return_value = self.client_socket
        
        # Create a client instance with manually configured properties
        self.client = C2Client(server_host='127.0.0.1', server_port=12345)
        self.client.socket = self.client_socket
        self.client.symmetric_key = self.test_symmetric_key
        self.client.hmac_key = self.test_hmac_key
        self.client.cipher_suite = self.cipher_suite
        
        # Disable actual threading in the client
        self.thread_patcher = patch('threading.Thread')
        self.mock_thread = self.thread_patcher.start()
        
        # Capture output for verification
        self.stdout_patcher = patch('sys.stdout', new_callable=io.StringIO)
        self.mock_stdout = self.stdout_patcher.start()
    
    def tearDown(self):
        """Clean up after test"""
        self.socket_patcher.stop()
        self.thread_patcher.stop()
        self.stdout_patcher.stop()
        self.logging_patcher.stop()
    
    def encrypt_message_for_client(self, message_dict):
        """Helper function to encrypt a message for the client"""
        # Convert dict to JSON string and encode
        json_data = json.dumps(message_dict).encode()
        
        # Encrypt with symmetric key
        encrypted_data = self.cipher_suite.encrypt(json_data)
        
        # Create HMAC
        h = hmac.HMAC(self.test_hmac_key, hashes.SHA256())
        h.update(encrypted_data)
        message_hmac = h.finalize()
        
        # Return message parts
        return (
            len(encrypted_data).to_bytes(4, 'big'),
            encrypted_data,
            message_hmac
        )
    
    def test_heartbeat_response(self):
        """Test client response to heartbeat"""
        # Create a heartbeat message
        heartbeat = {'type': 'heartbeat', 'timestamp': time.time()}
        
        # Track call to process_command
        process_called = False
        
        # Patch process_command to detect heartbeat processing
        original_process_command = self.client.process_command
        
        def mock_process(command):
            nonlocal process_called
            if command.get('type') == 'heartbeat':
                process_called = True
            return original_process_command(command)
        
        # Replace the function
        self.client.process_command = mock_process
        
        try:
            # Directly call process_command with the heartbeat
            self.client.process_command(heartbeat)
            
            # Check that our process flag was set
            self.assertTrue(process_called, "Heartbeat command was not processed")
        finally:
            # Restore original process_command
            self.client.process_command = original_process_command
    
    @patch('subprocess.run')
    def test_shell_command_response(self, mock_subprocess_run):
        """Test client response to shell commands"""
        # Mock subprocess.run to return a successful result
        mock_subprocess_run.return_value = MagicMock(
            stdout="Command output",
            stderr="",
            returncode=0
        )
        
        # Create a shell command message
        shell_cmd = {'type': 'shell', 'cmd': 'echo test', 'timestamp': time.time()}
        
        # Encrypt the command
        length_bytes, encrypted_data, message_hmac = self.encrypt_message_for_client(shell_cmd)
        
        # Queue the encrypted command parts for the client to receive
        self.client_socket.queue_recv_data(length_bytes)
        self.client_socket.queue_recv_data(encrypted_data)
        self.client_socket.queue_recv_data(message_hmac)
        
        # Create a flag to verify when send_response is called
        response_sent = {'called': False, 'response': None}
        
        def mock_send_response(response):
            response_sent['called'] = True
            response_sent['response'] = response
        
        # Replace the client's send_response method
        original_send_response = self.client.send_response
        self.client.send_response = mock_send_response
        
        # Replace the receive function to just call process_command directly
        self.client.process_command(shell_cmd)
        
        try:
            # Verify subprocess.run was called with the right command
            mock_subprocess_run.assert_called()
            cmd_args = mock_subprocess_run.call_args[0][0]
            self.assertIn('echo', cmd_args, "The command should contain 'echo'")
            
            # Check if response was sent
            self.assertTrue(response_sent['called'], "send_response was not called")
            response = response_sent['response']
            self.assertEqual(response['type'], 'shell_result')
            self.assertEqual(response['stdout'], "Command output")
            self.assertEqual(response['returncode'], 0)
        
        finally:
            # Restore original send_response
            self.client.send_response = original_send_response
    
    @patch('platform.system')
    @patch('platform.release')
    @patch('platform.machine')
    @patch('platform.processor')
    @patch('platform.node')
    def test_system_info_command(self, mock_node, mock_processor, mock_machine, 
                                 mock_release, mock_system):
        """Test client response to system_info command"""
        # Mock platform functions
        mock_system.return_value = "Linux"
        mock_release.return_value = "5.10.0"
        mock_machine.return_value = "x86_64"
        mock_processor.return_value = "x86_64"
        mock_node.return_value = "testhost"
        
        # Create a system_info command
        info_cmd = {'type': 'system_info', 'id': 'test_id', 'timestamp': time.time()}
        
        # Create a flag to verify send_response
        response_sent = {'called': False, 'response': None}
        
        def mock_send_response(response):
            response_sent['called'] = True
            response_sent['response'] = response
        
        # Replace client's send_response method
        original_send_response = self.client.send_response
        self.client.send_response = mock_send_response
        
        try:
            # Direct process_command call
            self.client.process_command(info_cmd)
            
            # Verify response was sent with system info
            self.assertTrue(response_sent['called'], "send_response was not called")
            response = response_sent['response']
            self.assertEqual(response['type'], 'system_info_result')
            self.assertEqual(response['id'], 'test_id')
            self.assertEqual(response['os'], "Linux")
            self.assertEqual(response['release'], "5.10.0")
            self.assertEqual(response['machine'], "x86_64")
            self.assertEqual(response['processor'], "x86_64")
            self.assertEqual(response['hostname'], "testhost")
        finally:
            # Restore original function
            self.client.send_response = original_send_response
    
    @patch('tempfile.NamedTemporaryFile')
    @patch('subprocess.run')
    def test_initial_payload_execution(self, mock_subprocess_run, mock_temp_file):
        """Test client handling of initial_payload command"""
        # Mock temporary file
        mock_temp = MagicMock()
        mock_temp.name = "/tmp/tempfile123.py"
        mock_temp_file.return_value.__enter__.return_value = mock_temp
        
        # Mock subprocess.run to return successful result
        mock_subprocess_run.return_value = MagicMock(
            stdout="Payload executed successfully",
            stderr="",
            returncode=0
        )
        
        # Create a direct mock for _execute_payload
        original_execute_payload = self.client._execute_payload
        
        # Track if the function was called
        execution_info = {'called': False, 'payload': None}
        
        def mock_execute(payload):
            execution_info['called'] = True
            execution_info['payload'] = payload
            return {
                'status': 'success',
                'output': 'Payload executed successfully',
                'error': '',
                'returncode': 0
            }
        
        # Replace the real function
        self.client._execute_payload = mock_execute
        
        # Create the test payload command
        payload_command = {
            'type': 'initial_payload',
            'payload': 'print("Test payload")',
            'payload_id': 'test-id-123',
            'timestamp': time.time()
        }
        
        # Track if send_response was called
        response_info = {'called': False, 'response': None}
        
        def mock_send_response(response):
            response_info['called'] = True
            response_info['response'] = response
        
        # Save and replace send_response
        original_send_response = self.client.send_response
        self.client.send_response = mock_send_response
        
        try:
            # Directly process the payload command
            self.client.process_command(payload_command)
            
            # Verify _execute_payload was called
            self.assertTrue(execution_info['called'], "_execute_payload was not called")
            self.assertEqual(execution_info['payload'], 'print("Test payload")')
            
            # Verify send_response was called with the right payload ID
            self.assertTrue(response_info['called'], "send_response was not called")
            self.assertEqual(response_info['response']['type'], 'payload_result')
            self.assertEqual(response_info['response']['payload_id'], 'test-id-123')
        
        finally:
            # Restore original functions
            self.client._execute_payload = original_execute_payload
            self.client.send_response = original_send_response

class TestClientServerIntegration(unittest.TestCase):
    """Integration tests between client and server"""
    
    def setUp(self):
        """Set up a real server and client in separate threads"""
        # Patch the logging setup to avoid file handler issues
        self.logging_patcher = patch('logging.FileHandler')
        self.mock_file_handler = self.logging_patcher.start()
        self.mock_file_handler.return_value = MagicMock()
        
        # Set up test server on a high port
        self.server = C2Server(host='127.0.0.1', port=9999)
        
        # Start server in a thread
        self.server_thread = threading.Thread(target=self.server.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Wait for server to start
        time.sleep(0.5)
        
        # Disable output capturing on client and server
        self.null_logger = MagicMock()
        self.server.logger = self.null_logger
        
        # Prepare for client
        self.client = None
    
    def tearDown(self):
        """Clean up server and client"""
        # Clean up client if created
        if self.client:
            self.client.cleanup()
        
        # Clean up server connections
        with self.server.client_lock:
            for client_id in list(self.server.clients.keys()):
                try:
                    self.server.clients[client_id]['socket'].close()
                except:
                    pass
            self.server.clients.clear()
        
        # Stop logging patch
        self.logging_patcher.stop()
    
    # The tests below are commented out because we don't want to 
    # run actual socket connections in unit tests. They are here
    # to show how integration tests could be constructed.
    """
    def test_client_connection(self):
        # Create a client that connects to test server
        self.client = C2Client(server_host='127.0.0.1', server_port=9999)
        self.client.logger = self.null_logger
        
        # Start client connection (this is designed to be non-blocking)
        client_thread = threading.Thread(target=self.client.connect_to_server)
        client_thread.daemon = True
        client_thread.start()
        
        # Wait for connection to establish
        time.sleep(1)
        
        # Verify client connected to server
        with self.server.client_lock:
            self.assertEqual(len(self.server.clients), 1)
    
    def test_server_task_to_client(self):
        # Create and connect client
        self.client = C2Client(server_host='127.0.0.1', server_port=9999)
        self.client.logger = self.null_logger
        
        # Create a mock for client's process_command
        original_process_command = self.client.process_command
        received_commands = []
        
        def mock_process_command(command):
            received_commands.append(command)
            return original_process_command(command)
        
        self.client.process_command = mock_process_command
        
        # Connect client and wait for connection
        self.client.connect_to_server()
        time.sleep(1)
        
        # Find client_id in server's client list
        client_id = None
        with self.server.client_lock:
            client_id = list(self.server.clients.keys())[0]
        
        # Add a task to the server
        task = {
            'type': 'shell',
            'cmd': 'echo test',
            'timestamp': time.time(),
            'target': client_id
        }
        self.server.add_task(task)
        
        # Wait for task to be processed
        time.sleep(1)
        
        # Verify client received task
        self.assertGreaterEqual(len(received_commands), 1)
        shell_commands = [cmd for cmd in received_commands if cmd.get('type') == 'shell']
        self.assertGreaterEqual(len(shell_commands), 1)
        self.assertEqual(shell_commands[0]['cmd'], 'echo test')
    """

if __name__ == '__main__':
    unittest.main() 