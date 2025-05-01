import os
import sys
import subprocess
import re
import json
from typing import Optional, List, Dict, Union

class LinuxPrivilegeEscalation:
    def __init__(self):
        self.is_root = os.geteuid() == 0

    def check_root(self) -> bool:
        """Check if current process has root privileges."""
        return self.is_root

    def check_suid_binaries(self) -> List[Dict[str, str]]:
        """Check for SUID binaries that can be exploited."""
        suid_binaries = []
        try:
            # Find all SUID binaries
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'],
                capture_output=True,
                text=True
            )
            
            known_exploitable = [
                'nmap', 'vim', 'find', 'bash', 'more', 'less',
                'nano', 'cp', 'mv', 'awk', 'man', 'python',
                'perl', 'ruby', 'lua', 'tclsh', 'expect'
            ]
            
            for binary in result.stdout.split('\n'):
                if binary:
                    binary_name = os.path.basename(binary)
                    if binary_name in known_exploitable:
                        suid_binaries.append({
                            'binary': binary,
                            'name': binary_name,
                            'exploitable': True
                        })
        except Exception:
            pass
        
        return suid_binaries

    def check_capabilities(self) -> List[Dict[str, str]]:
        """Check for Linux capabilities that can be exploited."""
        exploitable_caps = []
        try:
            # Get capabilities of all binaries
            result = subprocess.run(
                ['getcap', '-r', '/'],
                capture_output=True,
                text=True
            )
            
            dangerous_caps = [
                'cap_dac_read_search',
                'cap_dac_override',
                'cap_sys_admin',
                'cap_sys_ptrace',
                'cap_sys_module',
                'cap_sys_rawio'
            ]
            
            for line in result.stdout.split('\n'):
                if line:
                    parts = line.split('=')
                    if len(parts) == 2:
                        binary = parts[0].strip()
                        caps = parts[1].strip()
                        for cap in dangerous_caps:
                            if cap in caps:
                                exploitable_caps.append({
                                    'binary': binary,
                                    'capability': cap
                                })
        except Exception:
            pass
        
        return exploitable_caps

    def check_cron_jobs(self) -> List[Dict[str, str]]:
        """Check for vulnerable cron jobs."""
        vulnerable_jobs = []
        try:
            # Check system crontab
            with open('/etc/crontab', 'r') as f:
                for line in f:
                    if not line.startswith('#') and line.strip():
                        parts = line.split()
                        if len(parts) >= 6:
                            command = ' '.join(parts[5:])
                            if os.access(command.split()[0], os.W_OK):
                                vulnerable_jobs.append({
                                    'schedule': ' '.join(parts[:5]),
                                    'command': command,
                                    'reason': 'Writable command path'
                                })
            
            # Check user crontabs
            for user in os.listdir('/var/spool/cron/crontabs'):
                with open(f'/var/spool/cron/crontabs/{user}', 'r') as f:
                    for line in f:
                        if not line.startswith('#') and line.strip():
                            parts = line.split()
                            if len(parts) >= 6:
                                command = ' '.join(parts[5:])
                                if os.access(command.split()[0], os.W_OK):
                                    vulnerable_jobs.append({
                                        'user': user,
                                        'schedule': ' '.join(parts[:5]),
                                        'command': command,
                                        'reason': 'Writable command path'
                                    })
        except Exception:
            pass
        
        return vulnerable_jobs

    def check_writable_paths(self) -> List[Dict[str, str]]:
        """Check for writable paths in Linux system directories."""
        writable_paths = []
        system_paths = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/crontab',
            '/etc/init.d',
            '/etc/rc.local',
            '/etc/profile',
            '/etc/bash.bashrc',
            '/root/.bashrc',
            '/root/.ssh'
        ]
        
        for path in system_paths:
            if os.path.exists(path):
                if os.access(path, os.W_OK):
                    writable_paths.append({
                        'path': path,
                        'reason': 'Writable system file'
                    })
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        for name in files:
                            file_path = os.path.join(root, name)
                            if os.access(file_path, os.W_OK):
                                writable_paths.append({
                                    'path': file_path,
                                    'reason': 'Writable system file'
                                })
        
        return writable_paths

    def check_kernel_exploits(self) -> List[Dict[str, str]]:
        """Check for potential kernel exploits based on version."""
        potential_exploits = []
        try:
            # Get kernel version
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True
            )
            kernel_version = result.stdout.strip()
            
            # Known vulnerable kernel versions
            vulnerable_versions = {
                '2.6.32': ['Dirty COW', 'CVE-2016-5195'],
                '3.13.0': ['Dirty COW', 'CVE-2016-5195'],
                '4.4.0': ['Dirty COW', 'CVE-2016-5195'],
                '4.8.0': ['Dirty COW', 'CVE-2016-5195'],
                '4.9.0': ['Dirty COW', 'CVE-2016-5195']
            }
            
            for version, exploits in vulnerable_versions.items():
                if kernel_version.startswith(version):
                    potential_exploits.append({
                        'kernel_version': kernel_version,
                        'exploits': exploits
                    })
        except Exception:
            pass
        
        return potential_exploits

    def check_sudo_misconfig(self) -> List[Dict[str, str]]:
        """Check for sudo misconfigurations."""
        sudo_misconfigs = []
        try:
            # Get sudo rules
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'NOPASSWD' in line:
                    sudo_misconfigs.append({
                        'rule': line.strip(),
                        'reason': 'Passwordless sudo'
                    })
                elif 'ALL' in line and 'root' in line:
                    sudo_misconfigs.append({
                        'rule': line.strip(),
                        'reason': 'Full sudo access'
                    })
        except Exception:
            pass
        
        return sudo_misconfigs

    def check_environment_variables(self) -> List[Dict[str, str]]:
        """Check for exploitable environment variables."""
        exploitable_env = []
        try:
            # Check PATH
            path_dirs = os.environ.get('PATH', '').split(':')
            for directory in path_dirs:
                if os.access(directory, os.W_OK):
                    exploitable_env.append({
                        'variable': 'PATH',
                        'directory': directory,
                        'reason': 'Writable PATH directory'
                    })
            
            # Check LD_PRELOAD
            if 'LD_PRELOAD' in os.environ:
                exploitable_env.append({
                    'variable': 'LD_PRELOAD',
                    'value': os.environ['LD_PRELOAD'],
                    'reason': 'LD_PRELOAD is set'
                })
            
            # Check LD_LIBRARY_PATH
            if 'LD_LIBRARY_PATH' in os.environ:
                exploitable_env.append({
                    'variable': 'LD_LIBRARY_PATH',
                    'value': os.environ['LD_LIBRARY_PATH'],
                    'reason': 'LD_LIBRARY_PATH is set'
                })
        except Exception:
            pass
        
        return exploitable_env

    def check_system_info(self) -> Dict[str, str]:
        """Gather system information for privilege escalation."""
        system_info = {}
        try:
            # Get OS version
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        system_info[key.strip()] = value.strip().strip('"')
            
            # Get kernel version
            result = subprocess.run(
                ['uname', '-a'],
                capture_output=True,
                text=True
            )
            system_info['kernel'] = result.stdout.strip()
            
            # Get architecture
            result = subprocess.run(
                ['uname', '-m'],
                capture_output=True,
                text=True
            )
            system_info['architecture'] = result.stdout.strip()
        except Exception:
            pass
        
        return system_info

    def run_checks(self) -> Dict[str, Union[bool, List, Dict]]:
        """Run all Linux privilege escalation checks."""
        return {
            'is_root': self.check_root(),
            'suid_binaries': self.check_suid_binaries(),
            'capabilities': self.check_capabilities(),
            'cron_jobs': self.check_cron_jobs(),
            'writable_paths': self.check_writable_paths(),
            'kernel_exploits': self.check_kernel_exploits(),
            'sudo_misconfig': self.check_sudo_misconfig(),
            'environment_variables': self.check_environment_variables(),
            'system_info': self.check_system_info()
        } 