import os
import sys
import subprocess
import winreg
import ctypes
import tempfile
import shutil
import json
from typing import Optional, List, Dict, Union
from src.helpers.registry_manager import RegistryManager

class WindowsPrivilegeEscalation:
    def __init__(self):
        self.registry = RegistryManager()
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    def check_admin(self) -> bool:
        """Check if current process has admin privileges."""
        return self.is_admin

    def check_token_privileges(self) -> List[Dict[str, str]]:
        """Check for exploitable Windows token privileges."""
        exploitable_privileges = []
        try:
            # Use whoami to get token privileges
            result = subprocess.run(
                ['whoami', '/priv'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'Se' in line and 'Enabled' in line:
                    privilege = line.split()[0].strip()
                    if privilege in [
                        'SeImpersonatePrivilege',
                        'SeAssignPrimaryTokenPrivilege',
                        'SeTcbPrivilege',
                        'SeBackupPrivilege',
                        'SeRestorePrivilege',
                        'SeCreateTokenPrivilege',
                        'SeLoadDriverPrivilege',
                        'SeTakeOwnershipPrivilege',
                        'SeDebugPrivilege'
                    ]:
                        exploitable_privileges.append({
                            'privilege': privilege,
                            'status': 'Enabled'
                        })
        except Exception:
            pass
        
        return exploitable_privileges

    def check_dll_hijacking(self) -> List[Dict[str, str]]:
        """Check for DLL hijacking opportunities."""
        vulnerable_paths = []
        try:
            # Check common DLL search paths
            search_paths = [
                os.environ.get('SystemRoot', 'C:\\Windows'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64'),
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', ''),
                os.getcwd()
            ]
            
            for path in search_paths:
                if os.path.exists(path) and os.access(path, os.W_OK):
                    vulnerable_paths.append({
                        'path': path,
                        'reason': 'Writable DLL search path'
                    })
        except Exception:
            pass
        
        return vulnerable_paths

    def check_always_install_elevated(self) -> bool:
        """Check if AlwaysInstallElevated is enabled in both HKLM and HKCU."""
        try:
            hklm_value = self.registry.read_value(
                'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
                'AlwaysInstallElevated'
            )
            hkcu_value = self.registry.read_value(
                'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
                'AlwaysInstallElevated'
            )
            return hklm_value == 1 and hkcu_value == 1
        except Exception:
            return False

    def check_wsus(self) -> bool:
        """Check for WSUS exploitation opportunities."""
        try:
            # Check if WSUS is enabled
            wsus_enabled = self.registry.read_value(
                'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate',
                'WUServer'
            )
            return wsus_enabled is not None
        except Exception:
            return False

    def check_unquoted_service_path(self) -> List[Dict[str, str]]:
        """Check for unquoted service paths."""
        vulnerable_services = []
        try:
            # Query services
            result = subprocess.run(
                ['sc', 'query'],
                capture_output=True,
                text=True
            )
            
            services = [line.split()[1] for line in result.stdout.split('\n') 
                       if line.startswith('SERVICE_NAME:')]
            
            for service in services:
                try:
                    # Get service path
                    result = subprocess.run(
                        ['sc', 'qc', service],
                        capture_output=True,
                        text=True
                    )
                    
                    for line in result.stdout.split('\n'):
                        if 'BINARY_PATH_NAME' in line:
                            path = line.split(':', 1)[1].strip()
                            if ' ' in path and not path.startswith('"'):
                                vulnerable_services.append({
                                    'service': service,
                                    'path': path
                                })
                except Exception:
                    continue
        except Exception:
            pass
        
        return vulnerable_services

    def check_writable_service_path(self) -> List[Dict[str, str]]:
        """Check for writable service paths."""
        vulnerable_services = []
        try:
            # Query services
            result = subprocess.run(
                ['sc', 'query'],
                capture_output=True,
                text=True
            )
            
            services = [line.split()[1] for line in result.stdout.split('\n') 
                       if line.startswith('SERVICE_NAME:')]
            
            for service in services:
                try:
                    # Get service path
                    result = subprocess.run(
                        ['sc', 'qc', service],
                        capture_output=True,
                        text=True
                    )
                    
                    for line in result.stdout.split('\n'):
                        if 'BINARY_PATH_NAME' in line:
                            path = line.split(':', 1)[1].strip().strip('"')
                            if os.path.exists(path):
                                if os.access(os.path.dirname(path), os.W_OK):
                                    vulnerable_services.append({
                                        'service': service,
                                        'path': path
                                    })
                except Exception:
                    continue
        except Exception:
            pass
        
        return vulnerable_services

    def check_weak_service_permissions(self) -> List[Dict[str, str]]:
        """Check for services with weak permissions."""
        vulnerable_services = []
        try:
            # Query services
            result = subprocess.run(
                ['sc', 'query'],
                capture_output=True,
                text=True
            )
            
            services = [line.split()[1] for line in result.stdout.split('\n') 
                       if line.startswith('SERVICE_NAME:')]
            
            for service in services:
                try:
                    # Get service permissions
                    result = subprocess.run(
                        ['sc', 'sdshow', service],
                        capture_output=True,
                        text=True
                    )
                    
                    # Check for weak permissions
                    sd = result.stdout.strip()
                    if 'WD' in sd or 'BU' in sd:  # Weak DACL
                        vulnerable_services.append({
                            'service': service,
                            'security_descriptor': sd
                        })
                except Exception:
                    continue
        except Exception:
            pass
        
        return vulnerable_services

    def check_autologon_credentials(self) -> Optional[Dict[str, str]]:
        """Check for autologon credentials in registry."""
        try:
            # Check Winlogon registry keys
            username = self.registry.read_value(
                'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                'DefaultUserName'
            )
            
            password = self.registry.read_value(
                'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                'DefaultPassword'
            )
            
            if username and password:
                return {
                    'username': username,
                    'password': password
                }
        except Exception:
            pass
        return None

    def check_scheduled_tasks(self) -> List[Dict[str, str]]:
        """Check for vulnerable scheduled tasks."""
        vulnerable_tasks = []
        try:
            # List all scheduled tasks
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST', '/v'],
                capture_output=True,
                text=True
            )
            
            current_task = {}
            for line in result.stdout.split('\n'):
                if 'TaskName:' in line:
                    if current_task:
                        vulnerable_tasks.append(current_task)
                    current_task = {'name': line.split(':', 1)[1].strip()}
                elif 'Run As User:' in line:
                    current_task['user'] = line.split(':', 1)[1].strip()
                elif 'Task To Run:' in line:
                    current_task['command'] = line.split(':', 1)[1].strip()
            
            if current_task:
                vulnerable_tasks.append(current_task)
            
            # Filter for tasks running as SYSTEM or with weak permissions
            vulnerable_tasks = [
                task for task in vulnerable_tasks
                if task.get('user', '').upper() == 'SYSTEM' or
                'Everyone' in task.get('command', '')
            ]
        except Exception:
            pass
        
        return vulnerable_tasks

    def check_writable_paths(self) -> List[str]:
        """Check for writable paths in system directories."""
        writable_paths = []
        system_paths = [
            os.environ.get('SystemRoot', 'C:\\Windows'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp')
        ]
        
        for path in system_paths:
            if os.path.exists(path) and os.access(path, os.W_OK):
                writable_paths.append(path)
        
        return writable_paths

    def check_installed_software(self) -> List[Dict[str, str]]:
        """Check for installed software with known vulnerabilities."""
        vulnerable_software = []
        try:
            # Check installed software from registry
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                vulnerable_software.append({
                                    'name': name,
                                    'version': version
                                })
                            except WindowsError:
                                pass
                        i += 1
                    except WindowsError:
                        break
        except Exception:
            pass
        
        return vulnerable_software

    def check_system_info(self) -> Dict[str, str]:
        """Gather system information for privilege escalation."""
        system_info = {}
        try:
            # Get OS version
            result = subprocess.run(
                ['systeminfo'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'OS Name:' in line:
                    system_info['os_name'] = line.split(':', 1)[1].strip()
                elif 'OS Version:' in line:
                    system_info['os_version'] = line.split(':', 1)[1].strip()
                elif 'System Type:' in line:
                    system_info['system_type'] = line.split(':', 1)[1].strip()
        except Exception:
            pass
        
        return system_info

    def run_checks(self) -> Dict[str, Union[bool, List, Dict]]:
        """Run all Windows privilege escalation checks."""
        return {
            'is_admin': self.check_admin(),
            'token_privileges': self.check_token_privileges(),
            'dll_hijacking': self.check_dll_hijacking(),
            'always_install_elevated': self.check_always_install_elevated(),
            'wsus': self.check_wsus(),
            'unquoted_service_paths': self.check_unquoted_service_path(),
            'writable_service_paths': self.check_writable_service_path(),
            'weak_service_permissions': self.check_weak_service_permissions(),
            'autologon_credentials': self.check_autologon_credentials(),
            'vulnerable_scheduled_tasks': self.check_scheduled_tasks(),
            'writable_system_paths': self.check_writable_paths(),
            'installed_software': self.check_installed_software(),
            'system_info': self.check_system_info()
        } 