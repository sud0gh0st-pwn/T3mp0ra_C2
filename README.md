# Tempora - Secure C2 Framework

<div align="center">
  <img src="https://github.com/sud0gh0st-pwn/T3mp0ra_C2/blob/main/.github/img/Logo.png?raw=true" alt="Tempora" style="width:500px;"/>
</div>

Tempora is a robust, encrypted Command and Control (C2) framework designed for secure communication between a central server and distributed clients. Built with security and reliability in mind, Tempora features end-to-end encryption, asynchronous command dispatching, and resilient connections.

## Features

- **End-to-End Encryption**: Utilizes RSA for key exchange and Fernet for symmetric encryption
- **Message Authentication**: Implements HMAC for message integrity verification
- **Resilient Connections**: Automatic reconnection and session management
- **Interactive Command Interface**: Easy-to-use command line administration
- **Extensible Architecture**: Modular design for adding custom functionality
- **Comprehensive Logging**: Detailed activity monitoring and troubleshooting

## Architecture

Tempora operates on a server-client model:

1. **C2 Server**: Central command hub that distributes tasks and collects responses
2. **Clients**: Remote agents that execute commands and report system information

```
┌─────────────┐     Encrypted     ┌─────────────┐
│             │  Communication    │             │
│  C2 Server  │◄─────────────────►│   Client    │
│             │     Channel       │             │
└─────────────┘                   └─────────────┘
       ▲                                 ▲
       │                                 │
       ▼                                 ▼
┌─────────────┐                  ┌─────────────┐
│    Admin    │                  │    Target   │
│  Interface  │                  │    System   │
└─────────────┘                  └─────────────┘
```

## Installation

### Prerequisites

- Python 3.8+
- cryptography library

### Setup

1. Clone the repository:
```bash
git clone https://github.com/username/tempora.git
cd tempora
```

2. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create logging directory:
```bash
mkdir -p logs
```

## Usage

### Starting the C2 Server

```bash
python server.py
```

This will start the server on default port 5000 and launch the admin interface.

### Admin Commands

- `list` - Show all connected clients
- `task <type>:<command>` - Send a task to all connected clients
  - Example: `task shell:ls -la`
  - Example: `task system_info:`

### Deploying Clients

```bash
python client.py
```

By default, the client attempts to connect to localhost. For production deployments, modify the server address in the client code:

```python
client = C2Client(server_host='your.server.address', server_port=5000)
```

## Security Features

### Key Exchange Protocol

1. Server generates RSA key pair
2. Client connects and receives server's public key
3. Client generates symmetric and HMAC keys
4. Client encrypts these keys with server's public key
5. Server decrypts the keys using its private key
6. Both parties now have shared symmetric and HMAC keys

### Message Security

- All messages are encrypted with Fernet symmetric encryption
- Message integrity is verified with HMAC
- Protocol includes length prefixing to prevent fragmentation attacks

## Extending Functionality

### Adding New Command Types

The command processor in `client.py` can be extended to handle custom commands:

```python
def process_command(self, command):
    command_type = command.get('type')
    
    if command_type == 'my_custom_command':
        # Custom command handling logic
        result = self.execute_custom_action(command['parameters'])
        response = {
            'type': 'custom_result',
            'data': result
        }
        self.send_response(response)
```

## License

[MIT License](LICENSE)

## Disclaimer

This tool is designed for educational and authorized security testing purposes only. Usage of Tempora for attacking targets without prior mutual consent is illegal and prohibited.

This tool is for me and others who are interested to learn security concepts together 

## Acknowledgments

- [Cryptography.io](https://cryptography.io/) for the secure cryptographic primitives
- Contributors and security researchers who provided feedback
- Great Educational Resource @MariyaSha [Youtube]{www.youtube.com/PythonSimplified}
- Great Educational Resource @SteinOveHelset [Website]{https://codewithstein.com/}
---

© 2025 | Sudosec Solutions | All Rights Reserved
