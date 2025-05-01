import socket
import threading
import queue
import time
import logging
import asyncio
import aiohttp
import argparse
import json
import os
from typing import List, Dict, Optional, Tuple, Callable, Set, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from tqdm import tqdm
import concurrent.futures
import ipaddress
from collections import defaultdict
import math
import signal
import sys

# Local Imports
from helpers.db_operations import DBManager
from helpers.geoip_lookup import GeoIPLookup
from helpers.network_operations import NetworkOperations

@dataclass
class ScanConfig:
    """Configuration for network scanning"""
    timeout: float = 0.2
    max_threads: int = 500
    batch_size: int = 10000
    ports: List[int] = None
    retry_count: int = 1
    cache_results: bool = True
    show_progress: bool = True
    rate_limit: int = 5000
    geoip_cache_size: int = 1000000
    chunk_size: int = 10000
    common_ports_first: bool = True
    max_connections: int = 2000
    connection_timeout: float = 0.1
    scan_timeout: float = 0.2
    max_memory_usage: int = 1024 * 1024 * 1024
    checkpoint_interval: int = 100000
    resume_file: str = "scan_progress.json"
    max_retries: int = 3
    backoff_factor: float = 1.5
    log_level: str = "INFO"
    output_file: str = "scan_results.db"
    config_file: str = "scan_config.json"

    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanConfig':
        """Create config from dictionary"""
        return cls(**data)

    def to_dict(self) -> Dict:
        """Convert config to dictionary"""
        return asdict(self)

    def save(self, filename: str = None):
        """Save configuration to file"""
        filename = filename or self.config_file
        try:
            with open(filename, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")

    @classmethod
    def load(cls, filename: str) -> 'ScanConfig':
        """Load configuration from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                return cls.from_dict(data)
        except FileNotFoundError:
            return cls()
        except Exception as e:
            logging.error(f"Failed to load configuration: {e}")
            return cls()

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> 'ScanConfig':
        """Create config from command line arguments"""
        config = cls()
        
        # Update from config file if specified
        if args.config_file:
            config = cls.load(args.config_file)
        
        # Override with command line arguments
        for key, value in vars(args).items():
            if value is not None and hasattr(config, key):
                setattr(config, key, value)
        
        return config

def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Network Scanner')
    
    # Basic arguments
    parser.add_argument('start_ip', help='Starting IP address')
    parser.add_argument('end_ip', nargs='?', help='Ending IP address (optional)')
    
    # Configuration file
    parser.add_argument('--config-file', '-c', help='Configuration file path')
    
    # Scan parameters
    parser.add_argument('--timeout', type=float, help='Scan timeout in seconds')
    parser.add_argument('--max-threads', type=int, help='Maximum number of threads')
    parser.add_argument('--batch-size', type=int, help='Database batch size')
    parser.add_argument('--ports', type=str, help='Comma-separated list of ports')
    parser.add_argument('--retry-count', type=int, help='Number of retries per scan')
    parser.add_argument('--no-cache', action='store_true', help='Disable result caching')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress display')
    parser.add_argument('--rate-limit', type=int, help='Maximum scans per second')
    parser.add_argument('--geoip-cache-size', type=int, help='GeoIP cache size')
    parser.add_argument('--chunk-size', type=int, help='IP range chunk size')
    parser.add_argument('--no-common-first', action='store_true', help='Disable common ports first')
    parser.add_argument('--max-connections', type=int, help='Maximum concurrent connections')
    parser.add_argument('--connection-timeout', type=float, help='Connection timeout')
    parser.add_argument('--scan-timeout', type=float, help='Scan timeout')
    parser.add_argument('--max-memory', type=int, help='Maximum memory usage in bytes')
    parser.add_argument('--checkpoint-interval', type=int, help='Progress save interval')
    parser.add_argument('--resume-file', type=str, help='Progress file path')
    parser.add_argument('--max-retries', type=int, help='Maximum retries for failed scans')
    parser.add_argument('--backoff-factor', type=float, help='Exponential backoff factor')
    
    # Output options
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Logging level')
    parser.add_argument('--output-file', type=str, help='Output database file')
    
    return parser.parse_args()

@dataclass
class ScanProgress:
    """Tracks scan progress"""
    total_tasks: int = 0
    completed_tasks: int = 0
    open_ports: int = 0
    start_time: datetime = None
    current_ip: str = None
    current_port: int = None
    scan_rate: float = 0.0
    open_ports_by_ip: Dict[str, int] = None
    last_update_time: float = 0.0
    last_checkpoint: int = 0
    memory_usage: int = 0
    failed_scans: Dict[str, int] = None

    def __post_init__(self):
        self.open_ports_by_ip = defaultdict(int)
        self.failed_scans = defaultdict(int)
        self.last_update_time = time.time()
        self.memory_usage = 0

    def get_progress(self) -> float:
        """Get progress as percentage"""
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100

    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        if not self.start_time:
            return 0.0
        return (datetime.now() - self.start_time).total_seconds()

    def get_estimated_time_remaining(self) -> float:
        """Get estimated time remaining in seconds"""
        if self.completed_tasks == 0:
            return 0.0
        elapsed = self.get_elapsed_time()
        return (elapsed / self.completed_tasks) * (self.total_tasks - self.completed_tasks)

    def update_scan_rate(self):
        """Update the current scan rate"""
        current_time = time.time()
        time_diff = current_time - self.last_update_time
        if time_diff >= 1.0:
            self.scan_rate = self.completed_tasks / self.get_elapsed_time()
            self.last_update_time = current_time

    def update_open_ports(self, ip: str):
        """Update open ports count for an IP"""
        self.open_ports_by_ip[ip] += 1
        self.open_ports += 1

    def update_memory_usage(self):
        """Update memory usage tracking"""
        import psutil
        process = psutil.Process()
        self.memory_usage = process.memory_info().rss

    def should_checkpoint(self) -> bool:
        """Check if we should save progress"""
        return self.completed_tasks - self.last_checkpoint >= self.checkpoint_interval

    def to_dict(self) -> Dict:
        """Convert progress to dictionary for saving"""
        return {
            'completed_tasks': self.completed_tasks,
            'open_ports': self.open_ports,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'current_ip': self.current_ip,
            'current_port': self.current_port,
            'last_checkpoint': self.last_checkpoint,
            'failed_scans': dict(self.failed_scans)
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanProgress':
        """Create progress from saved dictionary"""
        progress = cls()
        progress.completed_tasks = data['completed_tasks']
        progress.open_ports = data['open_ports']
        progress.start_time = datetime.fromisoformat(data['start_time']) if data['start_time'] else None
        progress.current_ip = data['current_ip']
        progress.current_port = data['current_port']
        progress.last_checkpoint = data['last_checkpoint']
        progress.failed_scans = defaultdict(int, data['failed_scans'])
        return progress

class ScanResult:
    """Represents a single scan result"""
    def __init__(self, ip: str, port: int, is_open: bool, 
                 country: str = None, city: str = None, 
                 postcode: str = None, service: str = None,
                 banner: str = None):
        self.ip = ip
        self.port = port
        self.is_open = is_open
        self.country = country
        self.city = city
        self.postcode = postcode
        self.service = service
        self.banner = banner
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary for database insertion"""
        return {
            'IP_ADDRESS': self.ip,
            'PORT': self.port,
            'COUNTRY': self.country,
            'CITY': self.city,
            'POSTCODE': self.postcode,
            'SERVICE': self.service,
            'BANNER': self.banner,
            'TIMESTAMP': self.timestamp.isoformat()
        }

class NetworkScanner:
    def __init__(self, config: ScanConfig = None):
        """Initialize scanner with configuration"""
        self.config = config or ScanConfig()
        
        # Setup logging
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.db_manager = DBManager(self.config.output_file)
        self.geoip_lookup_city = GeoIPLookup("GeoIP2-City.mmdb")
        self.geoip_lookup_country = GeoIPLookup("GeoIP2-Country.mmdb")
        
        # Parse ports if provided as string
        if isinstance(self.config.ports, str):
            self.config.ports = [int(p) for p in self.config.ports.split(',')]
        elif self.config.ports is None:
            self.config.ports = [
                80, 443, 22, 21, 23, 25, 53, 110, 143, 445, 3389,
                135, 139, 1433, 3306, 5432, 8080, 8443, 5900, 27017
            ]
        
        # Initialize queues and caches
        self.scan_queue = asyncio.Queue()
        self.results_queue = asyncio.Queue()
        self.scan_cache = {}
        self.geoip_cache = {}
        self.progress = ScanProgress()
        
        # Setup database and connection pool
        self.initialize_database()
        self.connection_pool = aiohttp.TCPConnector(
            limit=self.config.max_connections,
            ttl_dns_cache=300,
            force_close=True
        )
        self.session = None
        self.is_running = True
        
        # Setup signal handlers
        self.setup_signal_handlers()

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(sig, frame):
            self.logger.info("Received shutdown signal, saving progress...")
            self.is_running = False
            self.save_progress()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def save_progress(self):
        """Save current scan progress"""
        try:
            import json
            with open(self.config.resume_file, 'w') as f:
                json.dump(self.progress.to_dict(), f)
            self.logger.info("Progress saved successfully")
        except Exception as e:
            self.logger.error(f"Failed to save progress: {e}")

    def load_progress(self) -> bool:
        """Load previous scan progress"""
        try:
            import json
            import os
            if os.path.exists(self.config.resume_file):
                with open(self.config.resume_file, 'r') as f:
                    data = json.load(f)
                self.progress = ScanProgress.from_dict(data)
                self.logger.info("Progress loaded successfully")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to load progress: {e}")
            return False

    async def init_session(self):
        """Initialize aiohttp session"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                connector=self.connection_pool,
                timeout=aiohttp.ClientTimeout(
                    total=None,
                    connect=self.config.connection_timeout,
                    sock_read=self.config.scan_timeout
                )
            )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    def initialize_database(self):
        """Initialize the database and create necessary tables"""
        if not self.db_manager.table_exists(self.table_name):
            self.db_manager.create_table(
                self.table_name,
                self.columns_definition,
                constraints=['UNIQUE(IP_ADDRESS, PORT)']
            )

    def setup_logging(self):
        """Configure logging for the scanner"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def update_progress(self, ip: str = None, port: int = None):
        """Update progress information"""
        self.progress.completed_tasks += 1
        if ip and port:
            self.progress.current_ip = ip
            self.progress.current_port = port
        self.progress.update_scan_rate()
        self.progress.update_memory_usage()

        if self.progress.should_checkpoint():
            self.save_progress()
            self.progress.last_checkpoint = self.progress.completed_tasks

    def print_progress(self):
        """Print current progress information"""
        if not self.config.show_progress:
            return

        progress = self.progress.get_progress()
        elapsed = self.progress.get_elapsed_time()
        remaining = self.progress.get_estimated_time_remaining()
        memory_usage = self.progress.memory_usage / (1024 * 1024)  # Convert to MB
        
        print(f"\rProgress: {progress:.2f}% | "
              f"Completed: {self.progress.completed_tasks}/{self.progress.total_tasks} | "
              f"Open Ports: {self.progress.open_ports} | "
              f"Rate: {self.progress.scan_rate:.1f} scans/s | "
              f"Memory: {memory_usage:.1f}MB | "
              f"Elapsed: {elapsed:.1f}s | "
              f"Remaining: {remaining:.1f}s | "
              f"Current: {self.progress.current_ip}:{self.progress.current_port}", end="")

    def get_geoip_info(self, ip: str) -> Tuple[str, str, str]:
        """Get GeoIP information with caching"""
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]
        
        country = self.geoip_lookup_country.get_country(ip)
        city = self.geoip_lookup_city.get_city(ip)
        postcode = self.geoip_lookup_city.get_postcode(ip)
        
        self.geoip_cache[ip] = (country, city, postcode)
        if len(self.geoip_cache) > self.config.geoip_cache_size:
            # Remove oldest entry
            self.geoip_cache.pop(next(iter(self.geoip_cache)))
        
        return country, city, postcode

    async def scan_port_async(self, ip: str, port: int) -> Optional[ScanResult]:
        """Asynchronous port scanning with retry logic"""
        if self.config.cache_results:
            cache_key = f"{ip}:{port}"
            if cache_key in self.scan_cache:
                return self.scan_cache[cache_key]

        # Rate limiting
        current_time = time.time()
        time_since_last_scan = current_time - self.last_scan_time
        if time_since_last_scan < 1.0 / self.config.rate_limit:
            await asyncio.sleep(1.0 / self.config.rate_limit - time_since_last_scan)
        self.last_scan_time = time.time()

        retry_count = 0
        while retry_count < self.config.max_retries:
            try:
                if await NetworkOperations.scan_port_async(ip, port, self.config.timeout):
                    service, banner = await NetworkOperations.detect_service_async(
                        ip, port, self.config.timeout
                    )
                    country, city, postcode = self.get_geoip_info(ip)
                    
                    result = ScanResult(
                        ip=ip, port=port, is_open=True,
                        country=country, city=city,
                        postcode=postcode, service=service,
                        banner=banner
                    )
                    
                    if self.config.cache_results:
                        self.scan_cache[cache_key] = result
                    
                    self.progress.update_open_ports(ip)
                    return result
                break
            except Exception as e:
                retry_count += 1
                if retry_count < self.config.max_retries:
                    await asyncio.sleep(self.config.backoff_factor ** retry_count)
                else:
                    self.progress.failed_scans[f"{ip}:{port}"] += 1
                    self.logger.debug(f"Port scan failed for {ip}:{port} after {retry_count} attempts: {e}")
        
        return ScanResult(ip=ip, port=port, is_open=False)

    def chunk_ip_range(self, start_ip: str, end_ip: str) -> Generator[List[str], None, None]:
        """Generate chunks of IP addresses for efficient scanning"""
        try:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            current_chunk = []
            
            for ip in range(int(start), int(end) + 1):
                current_chunk.append(str(ipaddress.IPv4Address(ip)))
                if len(current_chunk) >= self.config.chunk_size:
                    yield current_chunk
                    current_chunk = []
            
            if current_chunk:
                yield current_chunk
        except Exception as e:
            self.logger.error(f"Error generating IP range chunks: {e}")
            yield []

    async def scan_chunk(self, ip_chunk: List[str], ports: List[int]):
        """Scan a chunk of IP addresses"""
        tasks = []
        for ip in ip_chunk:
            for port in ports:
                if self.is_running:
                    tasks.append(self.scan_port_async(ip, port))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, ScanResult) and result.is_open:
                await self.results_queue.put(result)

    async def process_results(self):
        """Process scan results and store them in the database"""
        batch = []
        batch_size = self.config.batch_size
        
        try:
            while self.is_running:
                try:
                    result = await self.results_queue.get()
                    batch.append(result.to_dict())
                    
                    if len(batch) >= batch_size:
                        if self.db_manager.insert_many(self.table_name, list(batch[0].keys()), 
                                                     [tuple(d.values()) for d in batch]):
                            self.logger.info(f"Stored {len(batch)} results in batch")
                        else:
                            self.logger.error(f"Failed to store batch of {len(batch)} results")
                        batch = []
                    
                    self.results_queue.task_done()
                except asyncio.QueueEmpty:
                    if batch:
                        if self.db_manager.insert_many(self.table_name, list(batch[0].keys()), 
                                                     [tuple(d.values()) for d in batch]):
                            self.logger.info(f"Stored final batch of {len(batch)} results")
                        else:
                            self.logger.error(f"Failed to store final batch of {len(batch)} results")
                    break
        except Exception as e:
            self.logger.error(f"Error processing results: {e}")

    async def start_scan_async(self, start_ip: str, end_ip: str) -> None:
        """Start the network scan from a given IP range"""
        self.logger.info(f"Starting scan from IP range: {start_ip} - {end_ip}")
        
        # Try to resume previous scan
        if self.load_progress():
            self.logger.info(f"Resuming scan from {self.progress.completed_tasks} completed tasks")
        
        await self.init_session()
        
        # Calculate total tasks
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        total_ips = int(end) - int(start) + 1
        if not self.progress.start_time:
            self.progress = ScanProgress(
                total_tasks=total_ips * len(self.config.ports),
                start_time=datetime.now()
            )

        # Process results in a separate task
        results_task = asyncio.create_task(self.process_results())

        try:
            # First scan common ports
            if self.config.common_ports_first:
                common_ports = [80, 443, 22, 21, 23, 25, 53, 110, 143, 445, 3389]
                for ip_chunk in self.chunk_ip_range(start_ip, end_ip):
                    if not self.is_running:
                        break
                    await self.scan_chunk(ip_chunk, common_ports)
                    self.print_progress()

            # Then scan remaining ports
            if self.is_running:
                remaining_ports = [p for p in self.config.ports if p not in common_ports]
                for ip_chunk in self.chunk_ip_range(start_ip, end_ip):
                    if not self.is_running:
                        break
                    await self.scan_chunk(ip_chunk, remaining_ports)
                    self.print_progress()

        finally:
            self.is_running = False
            await self.close_session()
            await results_task
            self.save_progress()
            self.logger.info("Scan completed")

    def start_scan(self, start_ip: str, end_ip: str = None) -> None:
        """Start the network scan (wrapper for async version)"""
        if not end_ip:
            end_ip = start_ip
        asyncio.run(self.start_scan_async(start_ip, end_ip))

def main():
    """Main entry point"""
    args = parse_args()
    config = ScanConfig.from_args(args)
    
    # Save configuration if specified
    if args.config_file:
        config.save(args.config_file)
    
    scanner = NetworkScanner(config)
    scanner.start_scan(args.start_ip, args.end_ip)

if __name__ == "__main__":
    main()
