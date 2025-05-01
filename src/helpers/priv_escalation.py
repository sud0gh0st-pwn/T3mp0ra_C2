import os
import sys
import platform
from typing import Dict, Union, Optional
from src.helpers.windows_priv_esc import WindowsPrivilegeEscalation
from src.helpers.linux_priv_esc import LinuxPrivilegeEscalation
from src.helpers.macos_priv_esc import MacOSPrivilegeEscalation

class PrivilegeEscalation:
    def __init__(self):
        """Initialize the appropriate privilege escalation module based on OS."""
        self.os_type = platform.system().lower()
        self.priv_esc = None
        
        if self.os_type == 'windows':
            self.priv_esc = WindowsPrivilegeEscalation()
        elif self.os_type == 'linux':
            self.priv_esc = LinuxPrivilegeEscalation()
        elif self.os_type == 'darwin':  # macOS
            self.priv_esc = MacOSPrivilegeEscalation()
        else:
            raise NotImplementedError(f"Privilege escalation not implemented for {self.os_type}")

    def run_checks(self) -> Dict[str, Union[bool, list, dict]]:
        """Run all privilege escalation checks for the current OS."""
        if not self.priv_esc:
            raise RuntimeError("No privilege escalation module initialized")
        return self.priv_esc.run_checks()

    def get_os_specific_checks(self) -> Dict[str, str]:
        """Get a list of OS-specific checks available."""
        if not self.priv_esc:
            raise RuntimeError("No privilege escalation module initialized")
        
        checks = {}
        for method_name in dir(self.priv_esc):
            if method_name.startswith('check_') and callable(getattr(self.priv_esc, method_name)):
                method = getattr(self.priv_esc, method_name)
                if method.__doc__:
                    checks[method_name] = method.__doc__.strip()
        return checks

    def run_specific_check(self, check_name: str) -> Optional[Union[bool, list, dict]]:
        """Run a specific privilege escalation check."""
        if not self.priv_esc:
            raise RuntimeError("No privilege escalation module initialized")
        
        method_name = f"check_{check_name}"
        if not hasattr(self.priv_esc, method_name):
            raise ValueError(f"Check '{check_name}' not found for {self.os_type}")
        
        method = getattr(self.priv_esc, method_name)
        return method()

    def get_os_info(self) -> Dict[str, str]:
        """Get detailed OS information."""
        return {
            'os_type': self.os_type,
            'os_name': platform.system(),
            'os_version': platform.version(),
            'os_release': platform.release(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }

    def is_supported_os(self) -> bool:
        """Check if the current OS is supported."""
        return self.os_type in ['windows', 'linux', 'darwin']

    def get_available_techniques(self) -> Dict[str, str]:
        """Get a list of available privilege escalation techniques for the current OS."""
        if not self.priv_esc:
            raise RuntimeError("No privilege escalation module initialized")
        
        techniques = {}
        for method_name in dir(self.priv_esc):
            if method_name.startswith('check_') and callable(getattr(self.priv_esc, method_name)):
                method = getattr(self.priv_esc, method_name)
                if method.__doc__:
                    technique_name = method_name.replace('check_', '')
                    techniques[technique_name] = method.__doc__.strip()
        return techniques 