import os
import sys
import subprocess
import re
import json
import plistlib
from typing import Optional, List, Dict, Union

class MacOSPrivilegeEscalation:
    def __init__(self):
        self.is_root = os.geteuid() == 0

    def check_root(self) -> bool:
        """Check if current process has root privileges."""
        return self.is_root

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

    def check_launchd_services(self) -> List[Dict[str, str]]:
        """Check for vulnerable launchd services."""
        vulnerable_services = []
        try:
            # Check system launchd services
            system_services = [
                '/Library/LaunchDaemons',
                '/System/Library/LaunchDaemons'
            ]
            
            for service_dir in system_services:
                if os.path.exists(service_dir):
                    for service_file in os.listdir(service_dir):
                        if service_file.endswith('.plist'):
                            service_path = os.path.join(service_dir, service_file)
                            try:
                                with open(service_path, 'rb') as f:
                                    plist = plistlib.load(f)
                                    
                                    # Check for writable program paths
                                    if 'ProgramArguments' in plist:
                                        program = plist['ProgramArguments'][0]
                                        if os.access(program, os.W_OK):
                                            vulnerable_services.append({
                                                'service': service_file,
                                                'path': program,
                                                'reason': 'Writable program path'
                                            })
                            except Exception:
                                continue
        except Exception:
            pass
        
        return vulnerable_services

    def check_kext_misconfig(self) -> List[Dict[str, str]]:
        """Check for kernel extension misconfigurations."""
        vulnerable_kexts = []
        try:
            # Check for loaded kexts
            result = subprocess.run(
                ['kextstat'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'com.apple' not in line:  # Focus on third-party kexts
                    parts = line.split()
                    if len(parts) >= 2:
                        kext_id = parts[1]
                        vulnerable_kexts.append({
                            'kext': kext_id,
                            'reason': 'Third-party kernel extension'
                        })
        except Exception:
            pass
        
        return vulnerable_kexts

    def check_writable_paths(self) -> List[Dict[str, str]]:
        """Check for writable paths in macOS system directories."""
        writable_paths = []
        system_paths = [
            '/etc/passwd',
            '/etc/sudoers',
            '/etc/hosts',
            '/Library/LaunchDaemons',
            '/Library/StartupItems',
            '/Library/Preferences',
            '/Library/Preferences/SystemConfiguration',
            '/Library/Application Support',
            '/private/etc',
            '/private/var'
        ]
        
        for path in system_paths:
            if os.path.exists(path):
                if os.access(path, os.W_OK):
                    writable_paths.append({
                        'path': path,
                        'reason': 'Writable system path'
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
            
            # Check DYLD_INSERT_LIBRARIES
            if 'DYLD_INSERT_LIBRARIES' in os.environ:
                exploitable_env.append({
                    'variable': 'DYLD_INSERT_LIBRARIES',
                    'value': os.environ['DYLD_INSERT_LIBRARIES'],
                    'reason': 'DYLD_INSERT_LIBRARIES is set'
                })
            
            # Check DYLD_LIBRARY_PATH
            if 'DYLD_LIBRARY_PATH' in os.environ:
                exploitable_env.append({
                    'variable': 'DYLD_LIBRARY_PATH',
                    'value': os.environ['DYLD_LIBRARY_PATH'],
                    'reason': 'DYLD_LIBRARY_PATH is set'
                })
        except Exception:
            pass
        
        return exploitable_env

    def check_system_info(self) -> Dict[str, str]:
        """Gather system information for privilege escalation."""
        system_info = {}
        try:
            # Get macOS version
            result = subprocess.run(
                ['sw_vers'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    system_info[key.strip()] = value.strip()
            
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

    def check_sip_status(self) -> Dict[str, str]:
        """Check System Integrity Protection status."""
        sip_status = {}
        try:
            result = subprocess.run(
                ['csrutil', 'status'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'System Integrity Protection status' in line:
                    sip_status['status'] = line.split(':')[1].strip()
                elif 'Configuration' in line:
                    sip_status['configuration'] = line.split(':')[1].strip()
        except Exception:
            pass
        
        return sip_status

    def check_gatekeeper_status(self) -> Dict[str, str]:
        """Check Gatekeeper status."""
        gatekeeper_status = {}
        try:
            result = subprocess.run(
                ['spctl', '--status'],
                capture_output=True,
                text=True
            )
            gatekeeper_status['status'] = result.stdout.strip()
        except Exception:
            pass
        
        return gatekeeper_status

    def run_checks(self) -> Dict[str, Union[bool, List, Dict]]:
        """Run all macOS privilege escalation checks."""
        return {
            'is_root': self.check_root(),
            'sudo_misconfig': self.check_sudo_misconfig(),
            'launchd_services': self.check_launchd_services(),
            'kext_misconfig': self.check_kext_misconfig(),
            'writable_paths': self.check_writable_paths(),
            'environment_variables': self.check_environment_variables(),
            'sip_status': self.check_sip_status(),
            'gatekeeper_status': self.check_gatekeeper_status(),
            'system_info': self.check_system_info()
        } 