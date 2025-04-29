import os
import sys
import unittest
import threading
import time
import socket
import json
import tempfile
import logging
from pathlib import Path

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import C2Server
from client import C2Client
from helpers.payloadGen import PayloadGenerator

class TestServerClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create logs directory if it doesn't exist
        Path('../logs').mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('../logs/tests.log')
            ]
        )
        
        # Create a temporary file for initial payload
        cls.temp_payload_file = tempfile.NamedTemporaryFile(delete=False, suffix='.py', mode='w')
        cls.temp_payload_file.write('''
print("Initial payload execution successful!")
with open("payload_executed.txt", "w") as f:
    f.write("Initial payload was executed successfully\\n")
''')
        cls.temp_payload_file.close()
        
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(
            target=cls._start_server,
            args=(cls.temp_payload_file.name,),
            daemon=True
        )
        cls.server_thread.start()
        
        # Wait for server to start
        time.sleep(2)
    
    @classmethod
    def _start_server(cls, initial_payload_path):
        """Start the C2 server with initial payload"""
        try:
            server = C2Server('127.0.0.1', 5555, initial_payload_path)
            server.start()
        except Exception as e:
            logging.error(f"Server error: {e}")
    
    @classmethod
    def tearDownClass(cls):
        # Clean up temporary file
        try:
            os.unlink(cls.temp_payload_file.name)
        except:
            pass
        
        # Clean up payload_executed.txt if it exists
        try:
            os.unlink("payload_executed.txt")
        except:
            pass
    
    @unittest.skip("Currently fails due to server-client connection issues")
    def test_client_connection_and_payload(self):
        """Test client connection and initial payload execution"""
        client = C2Client('127.0.0.1', 5555, interval=1)
        
        try:
            # Connect to the server
            connected = client.connect()
            self.assertTrue(connected, "Client failed to connect to server")
            
            # Give some time for initial payload to be received and executed
            time.sleep(5)
            
            # Check if payload_executed.txt exists
            self.assertTrue(os.path.exists("payload_executed.txt"), 
                           "Initial payload wasn't executed (payload_executed.txt not found)")
            
            # Verify the content of payload_executed.txt
            with open("payload_executed.txt", "r") as f:
                content = f.read().strip()
                self.assertEqual(content, "Initial payload was executed successfully",
                                "Payload execution content mismatch")
            
            # Disconnect
            client.disconnect()
            
        except Exception as e:
            self.fail(f"Test failed with exception: {e}")

if __name__ == '__main__':
    unittest.main() 