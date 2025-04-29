# Tempora - Secure C2 Framework

<div align="center">
  <img src="https://github.com/sud0gh0st-pwn/T3mp0ra_C2/blob/main/.github/img/Logo.png?raw=true" alt="Tempora" style="width:500px;"/>
  
  [![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
  [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
  [![Redis](https://img.shields.io/badge/redis-6.0%2B-red.svg)](https://redis.io/)
  [![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
  [![Security](https://img.shields.io/badge/security-encrypted-brightgreen.svg)](#security-features)
</div>

Tempora is a robust, encrypted Command and Control (C2) framework designed for secure communication between a central server and distributed clients. Built with security and reliability in mind, Tempora features end-to-end encryption, asynchronous command dispatching, and resilient connections.

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Security Features](#-security-features)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

## ✨ Features

- **End-to-End Encryption**: Utilizes RSA for key exchange and Fernet for symmetric encryption
- **Message Authentication**: Implements HMAC for message integrity verification
- **Resilient Connections**: Automatic reconnection and session management
- **Interactive Command Interface**: Easy-to-use command line administration with enhanced features
- **Extensible Architecture**: Modular design for adding custom functionality
- **Comprehensive Logging**: Detailed activity monitoring and troubleshooting
- **Redis Integration**: Message queue for scalable and reliable command distribution
- **Thread-Safe Operations**: Robust handling of concurrent connections and shared resources
- **Initial Payload Delivery**: Automatic payload execution upon client connection
- **Web Interface**: Modern web-based administration panel
- **Real-time Monitoring**: Live updates of client status and task execution
- **Multi-client Management**: Simultaneous control of multiple clients
- **Task Scheduling**: Schedule commands for future execution
- **Data Export**: Export client data and task history

## 🏗 Architecture

Tempora operates on a server-client model with a modern web interface:

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
│    Web      │                  │    Target   │
│  Interface  │                  │    System   │
└─────────────┘                  └─────────────┘
       ▲
       │
       ▼
┌─────────────┐
│    Redis    │
│   Message   │
│    Queue    │
└─────────────┘
```

## 🚀 Installation

### Prerequisites

- Python 3.8+
- Redis server 6.0+
- Docker and Docker Compose (optional, for containerized deployment)
- Node.js 14+ (for web interface)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/sud0gh0st-pwn/T3mp0ra_C2.git
cd T3mp0ra_C2
```

2. Create and activate virtual environment:
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Unix or MacOS:
source .venv/bin/activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Install Node.js dependencies (for web interface):
```bash
cd src/frontend
npm install
```

5. Create necessary directories:
```bash
mkdir -p logs data/redis
```

6. Set up Redis:

   a. Using the system's Redis installation:
   ```bash
   # Install Redis (Ubuntu/Debian)
   sudo apt update
   sudo apt install redis-server
   
   # Start Redis service
   sudo systemctl start redis-server
   sudo systemctl enable redis-server
   ```

   b. Using Docker (recommended):
   ```bash
   docker run --name tempora-redis -p 6379:6379 -v $(pwd)/data/redis:/data -d redis:alpine redis-server --appendonly yes
   ```

7. Configure your environment:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

## 💻 Usage

### Starting the C2 Server

1. Start Redis if not running:
```bash
# If using system Redis
sudo systemctl start redis-server

# If using Docker
docker start tempora-redis
```

2. Start the C2 server:
```bash
python src/server.py [IP] [PORT] [INITIAL_PAYLOAD_PATH]
```

3. Start the web interface:
```bash
cd src/frontend
python run.py --port 5001
```

4. Or use Docker Compose for the entire stack:
```bash
docker-compose up -d
```

### Web Interface Features

- **Dashboard**: Overview of server status and connected clients
- **Client Management**: View and manage connected clients
- **Task Management**: Create and monitor tasks
- **Settings**: Configure server parameters
- **System Information**: Monitor server resources
- **Logs**: View and filter system logs

### Command Line Interface

The admin interface supports the following commands:

- `help` - Display available commands
- `list` - Show all connected clients
- `task <type>:<command>` - Send a task to the currently targeted client
- `target <client_id>` - Set a client as the target for commands
- `info <client_id>` - Display detailed information about a client
- `status` - Show server status
- `kill <client_id>` - Force disconnect a client
- `history` - Show command history
- `clear` - Clear the console
- `exit` - Terminate the server

### Deploying Clients

```bash
python src/client.py [SERVER_IP] [SERVER_PORT] [INTERVAL]
```

Parameters:
- `SERVER_IP`: IP address of the C2 server (default: 127.0.0.1)
- `SERVER_PORT`: Port of the C2 server (default: 4444)
- `INTERVAL`: Status update interval in seconds (default: 5)

## 🔒 Security Features

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
- Redis communications secured with TLS (optional)
- CSRF protection for web interface
- Session management and authentication
- Secure password storage

## 🛠 Development

### Project Structure

```
tempora/
├── src/
│   ├── frontend/          # Web interface
│   ├── server.py          # C2 server
│   ├── client.py          # Client implementation
│   └── api.py            # API endpoints
├── tests/                 # Test suite
├── data/                  # Data storage
├── logs/                  # Log files
└── config/               # Configuration files
```

### Adding New Features

1. Create a new branch:
```bash
git checkout -b feature/new-feature
```

2. Make your changes and commit:
```bash
git add .
git commit -m "Add new feature"
```

3. Push and create a pull request:
```bash
git push origin feature/new-feature
```

### Testing

Run the test suite:
```bash
cd src
python -m pytest tests/
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for educational and authorized security testing purposes only. Usage of Tempora for attacking targets without prior mutual consent is illegal and prohibited.

## 🙏 Acknowledgments

- [Cryptography.io](https://cryptography.io/) for the secure cryptographic primitives
- [Redis](https://redis.io/) for reliable message queuing
- [Flask](https://flask.palletsprojects.com/) for the web interface
- Contributors and security researchers who provided feedback
- Great Educational Resource @MariyaSha [Youtube](https://www.youtube.com/PythonSimplified/) - Python
- Great Educational Resource @SteinOveHelset [Website](https://codewithstein.com/) - Python
- Great Educational Resource @JohnHammond [Youtube](https://youtube.com/johnhammond010) - Security

---

© 2025 | Sudosec Solutions | All Rights Reserved
