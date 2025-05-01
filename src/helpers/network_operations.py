import subprocess
import socket
from typing import Optional, Tuple

class NetworkOperations:
    @staticmethod
    def host_ping(ip: str) -> Optional[int]:
        try:
            p = subprocess.Popen('ping ' + ip, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.wait()
            for line in p.stdout:
                output = line.rstrip().decode('UTF-8')
                print(output)
            return p.poll()
        except Exception as e:
            print(f"Error in host_ping: {e}")
            return None

    @staticmethod
    def detect_service(ip: str, port: int, timeout: float = 0.7) -> Tuple[Optional[str], Optional[str]]:
        """Enhanced service detection with banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            banner = None
            service = None
            
            # HTTP/HTTPS
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                response = sock.recv(1024)
                if b"HTTP" in response:
                    service = "HTTP"
                    banner = response.decode('utf-8', errors='ignore').split('\n')[0]
            
            # SSH
            elif port == 22:
                sock.send(b"SSH-2.0-OpenSSH_7.9\r\n")
                response = sock.recv(1024)
                if b"SSH" in response:
                    service = "SSH"
                    banner = response.decode('utf-8', errors='ignore')
            
            # FTP
            elif port == 21:
                response = sock.recv(1024)
                if b"FTP" in response:
                    service = "FTP"
                    banner = response.decode('utf-8', errors='ignore')
                    sock.send(b"USER anonymous\r\n")
                    response = sock.recv(1024)
                    banner += response.decode('utf-8', errors='ignore')
            
            # SMTP
            elif port == 25:
                response = sock.recv(1024)
                if b"SMTP" in response or b"ESMTP" in response:
                    service = "SMTP"
                    banner = response.decode('utf-8', errors='ignore')
                    sock.send(b"EHLO test\r\n")
                    response = sock.recv(1024)
                    banner += response.decode('utf-8', errors='ignore')
            
            # POP3
            elif port == 110:
                response = sock.recv(1024)
                if b"+OK" in response:
                    service = "POP3"
                    banner = response.decode('utf-8', errors='ignore')
            
            # IMAP
            elif port == 143:
                response = sock.recv(1024)
                if b"* OK" in response:
                    service = "IMAP"
                    banner = response.decode('utf-8', errors='ignore')
            
            # RDP
            elif port == 3389:
                sock.send(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
                response = sock.recv(1024)
                if b"Microsoft" in response:
                    service = "RDP"
                    banner = response.decode('utf-8', errors='ignore')
            
            # DNS
            elif port == 53:
                service = "DNS"
                banner = "DNS Service Detected"
            
            # SMB
            elif port in [139, 445]:
                sock.send(b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00")
                response = sock.recv(1024)
                if b"SMB" in response:
                    service = "SMB"
                    banner = response.decode('utf-8', errors='ignore')
            
            # MySQL
            elif port == 3306:
                response = sock.recv(1024)
                if b"MySQL" in response:
                    service = "MySQL"
                    banner = response.decode('utf-8', errors='ignore')
            
            # PostgreSQL
            elif port == 5432:
                sock.send(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
                response = sock.recv(1024)
                if b"PostgreSQL" in response:
                    service = "PostgreSQL"
                    banner = response.decode('utf-8', errors='ignore')
            
            # MongoDB
            elif port == 27017:
                sock.send(b"\x3f\x00\x00\x00\x3f\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x01\x00\x00\x00\x21\x00\x00\x00\x02\x67\x65\x74\x4c\x6f\x67\x00\x10\x00\x00\x00\x73\x74\x61\x72\x74\x75\x70\x57\x61\x72\x6e\x69\x6e\x67\x73\x00\x00")
                response = sock.recv(1024)
                if b"MongoDB" in response:
                    service = "MongoDB"
                    banner = response.decode('utf-8', errors='ignore')
            
            # Redis
            elif port == 6379:
                sock.send(b"INFO\r\n")
                response = sock.recv(1024)
                if b"redis_version" in response:
                    service = "Redis"
                    banner = response.decode('utf-8', errors='ignore')
            
            # Elasticsearch
            elif port == 9200:
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                response = sock.recv(1024)
                if b"elasticsearch" in response.lower():
                    service = "Elasticsearch"
                    banner = response.decode('utf-8', errors='ignore')
            
            # VNC
            elif port == 5900:
                response = sock.recv(1024)
                if b"RFB" in response:
                    service = "VNC"
                    banner = response.decode('utf-8', errors='ignore')
            
            sock.close()
            return service, banner
            
        except Exception:
            return None, None

    @staticmethod
    def scan_port(ip: str, port: int, timeout: float = 0.7) -> bool:
        """Scan a single port on an IP address"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False