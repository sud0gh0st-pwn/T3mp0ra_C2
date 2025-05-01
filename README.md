# Tempora - Secure C2 Framework

<div align="center">
  <img src="https://github.com/sud0gh0st-pwn/T3mp0ra_C2/blob/main/.github/img/Logo.png?raw=true" alt="Tempora" style="width:500px;"/>
  
  [![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
  [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
  [![Redis](https://img.shields.io/badge/redis-6.0%2B-red.svg)](https://redis.io/)
  [![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
  [![Security](https://img.shields.io/badge/security-encrypted-brightgreen.svg)](#security-features)
  [![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](#documentation)
  [![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
  [![Code Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen.svg)](#)
  [![Last Commit](https://img.shields.io/github/last-commit/sud0gh0st-pwn/T3mp0ra_C2.svg)](#)
  [![Python](https://img.shields.io/badge/python-67.3%25-blue.svg)](#)
  [![HTML](https://img.shields.io/badge/html-18.3%25-orange.svg)](#)
  [![TypeScript](https://img.shields.io/badge/typescript-12.8%25-blue.svg)](#)
  [![CSS](https://img.shields.io/badge/css-1.6%25-purple.svg)](#)
</div>

Tempora is a robust, encrypted Command and Control (C2) framework designed for secure communication between a central server and distributed clients. Built with security and reliability in mind, Tempora features end-to-end encryption, asynchronous command dispatching, and resilient connections.

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Architecture](#-architecture)
- [Languages](#-languages)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Security Features](#-security-features)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)
- [FAQ](#-faq)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)

## 💻 Languages

Tempora is built using a modern stack of technologies:

- **Python (67.3%)**: Core server functionality, client implementation, and backend services
- **HTML (18.3%)**: Web interface structure and templates
- **TypeScript (12.8%)**: Frontend interactivity and type-safe code
- **CSS (1.6%)**: Styling and responsive design

### Technology Stack

- **Backend**:
  - Python 3.8+ for core functionality
  - Flask for web server
  - Redis for message queuing
  - SQLite for data storage

- **Frontend**:
  - TypeScript for type-safe development
  - Bootstrap for responsive design
  - jQuery for DOM manipulation
  - Custom CSS for styling

- **Development Tools**:
  - Git for version control
  - Docker for containerization
  - pytest for testing
  - ESLint for TypeScript linting

## ⚡ Quick Start

Get up and running in minutes:

```bash
# Clone the repository
git clone https://github.com/sud0gh0st-pwn/T3mp0ra_C2.git
cd T3mp0ra_C2

# Set up the environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Start Redis (using Docker)
docker run --name tempora-redis -p 6379:6379 -d redis:alpine

# Start the server
python src/server.py

# Start the web interface
cd src/frontend
python run.py
```

Visit `http://localhost:5001` to access the web interface.

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
- **Network Reconnaissance**: Built-in tools for network scanning and enumeration
  - IP Range Scanner with configurable parameters
  - Service Detection
  - GeoIP Location (using MaxMind GeoLite2 databases)
  - Results caching and export capabilities
- **Privilege Escalation**: Built-in tools for privilege escalation analysis
  - System Information Collection
  - Common Misconfigurations Detection
  - Exploit Suggestions
  - Automated Checks for Common Vulnerabilities

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

## 🔍 Recon Tools

### Network Scanner

The built-in network scanner provides comprehensive network reconnaissance capabilities:

- **IP Range Scanning**: Scan entire subnets or specific IP ranges
- **Port Configuration**: 
  - Scan specific ports or port ranges
  - Common ports scanning optimization
  - Service version detection
- **Performance Settings**:
  - Configurable thread count
  - Rate limiting
  - Connection timeout
  - Maximum retries
- **Resource Management**:
  - Chunk size for IP ranges
  - Database batch operations
  - Connection pooling
- **Results**:
  - Real-time progress monitoring
  - GeoIP information for discovered hosts
  - Export results in multiple formats
  - Results caching for faster subsequent scans

### Usage

Access the recon tools through:
1. Web Interface: Navigate to the Recon section
2. Configure scan parameters
3. Monitor progress in real-time
4. View and export results

## 🔐 Privilege Escalation Tools

### System Analysis

The built-in privilege escalation tools provide comprehensive system analysis capabilities:

- **System Information Collection**:
  - OS and kernel version
  - Installed packages and versions
  - Running services and processes
  - User and group information
  - File permissions and ownership
  - Network configuration
  - Scheduled tasks and cron jobs

- **Vulnerability Detection**:
  - SUID/SGID binaries
  - World-writable files and directories
  - Weak file permissions
  - Misconfigured services
  - Known vulnerable software versions
  - Password hashes in configuration files

- **Exploit Suggestions**:
  - Based on system configuration
  - Known vulnerabilities in installed software
  - Common misconfigurations
  - Custom exploit suggestions

- **Results**:
  - Detailed report generation
  - Risk assessment
  - Remediation suggestions
  - Export capabilities

### Usage

Access the privilege escalation tools through:
1. Web Interface: Navigate to the Recon section
2. Select "Privilege Escalation" tool
3. Configure analysis parameters
4. View and export results

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

## 📙 Configuration

### Environment Variables

Create a `.env` file with the following settings:

```env
# Server Configuration
SERVER_IP=0.0.0.0
SERVER_PORT=4444
WEB_PORT=5001

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Security Settings
ENCRYPTION_KEY_LENGTH=2048
SESSION_TIMEOUT=3600
MAX_LOGIN_ATTEMPTS=3

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/tempora.log

# Recon Settings
SCAN_TIMEOUT=5
MAX_SCAN_THREADS=100
GEOIP_DB_PATH=data/GeoLite2-City.mmdb
```

### Web Interface Configuration

Customize the web interface through `src/frontend/config.py`:

```python
# Theme settings
THEME = {
    'primary_color': '#007bff',
    'secondary_color': '#6c757d',
    'dark_mode': False
}

# Dashboard settings
DASHBOARD = {
    'refresh_interval': 10,
    'max_clients_display': 10,
    'max_tasks_display': 10
}
```

## ❓ FAQ

### General Questions

**Q: What makes Tempora different from other C2 frameworks?**
A: Tempora combines enterprise-grade security with user-friendly interfaces, offering both web and CLI administration, built-in reconnaissance tools, and privilege escalation analysis.

**Q: Is Tempora suitable for production use?**
A: Yes, Tempora is designed for production environments with features like encryption, authentication, and logging. However, always test thoroughly in a controlled environment first.

### Technical Questions

**Q: How do I handle Redis connection issues?**
A: Check the Redis service status, verify connection settings in `.env`, and ensure proper network connectivity. See [Troubleshooting](#-troubleshooting) for more details.

**Q: Can I customize the web interface?**
A: Yes, the web interface is highly customizable through the configuration files and supports custom themes.

## 🔧 Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```bash
   # Check Redis status
   docker ps | grep redis
   # Check logs
   docker logs tempora-redis
   ```

2. **Web Interface Not Loading**
   - Verify port availability
   - Check firewall settings
   - Review web server logs

3. **Client Connection Issues**
   - Verify network connectivity
   - Check server IP/port configuration
   - Review client logs

### Log Files

- Server logs: `logs/server.log`
- Web interface logs: `logs/web.log`
- Client logs: `logs/client.log`

## 🗺️ Roadmap

### Current Development

- [x] Basic C2 functionality
- [x] Web interface
- [x] Network reconnaissance
- [x] Privilege escalation tools
- [ ] Advanced payload generation
- [ ] Multi-platform support
- [ ] API documentation
- [ ] Performance optimizations

### Future Features

- [ ] Mobile client support
- [ ] Advanced persistence mechanisms
- [ ] Custom module development
- [ ] Integration with threat intelligence feeds
- [ ] Automated reporting
- [ ] Advanced evasion techniques
