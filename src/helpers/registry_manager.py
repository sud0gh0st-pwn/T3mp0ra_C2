import winreg
import os
import sys
import json
from typing import Optional, Dict, List, Union, Tuple

class RegistryManager:
    def __init__(self):
        self.hives = {
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKCR': winreg.HKEY_CLASSES_ROOT,
            'HKU': winreg.HKEY_USERS,
            'HKCC': winreg.HKEY_CURRENT_CONFIG
        }
        
        self.value_types = {
            'REG_SZ': winreg.REG_SZ,
            'REG_BINARY': winreg.REG_BINARY,
            'REG_DWORD': winreg.REG_DWORD,
            'REG_QWORD': winreg.REG_QWORD,
            'REG_MULTI_SZ': winreg.REG_MULTI_SZ,
            'REG_EXPAND_SZ': winreg.REG_EXPAND_SZ
        }

    def _parse_key_path(self, key_path: str) -> Tuple[int, str]:
        """Parse registry key path into hive and subkey."""
        parts = key_path.split('\\', 1)
        if len(parts) != 2:
            raise ValueError("Invalid registry key path format")
        
        hive_name = parts[0].upper()
        if hive_name not in self.hives:
            raise ValueError(f"Unknown registry hive: {hive_name}")
        
        return self.hives[hive_name], parts[1]

    def read_value(self, key_path: str, value_name: str) -> Optional[Union[str, int, bytes, List[str]]]:
        """Read a registry value."""
        try:
            hive, subkey = self._parse_key_path(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                value, value_type = winreg.QueryValueEx(key, value_name)
                return value
        except WindowsError:
            return None

    def write_value(self, key_path: str, value_name: str, value: Union[str, int, bytes, List[str]], 
                   value_type: str = 'REG_SZ') -> bool:
        """Write a registry value."""
        try:
            hive, subkey = self._parse_key_path(key_path)
            if value_type not in self.value_types:
                raise ValueError(f"Unknown value type: {value_type}")
            
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, value_name, 0, self.value_types[value_type], value)
                return True
        except WindowsError:
            return False

    def create_key(self, key_path: str) -> bool:
        """Create a registry key."""
        try:
            hive, subkey = self._parse_key_path(key_path)
            winreg.CreateKey(hive, subkey)
            return True
        except WindowsError:
            return False

    def delete_key(self, key_path: str) -> bool:
        """Delete a registry key."""
        try:
            hive, subkey = self._parse_key_path(key_path)
            winreg.DeleteKey(hive, subkey)
            return True
        except WindowsError:
            return False

    def delete_value(self, key_path: str, value_name: str) -> bool:
        """Delete a registry value."""
        try:
            hive, subkey = self._parse_key_path(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, value_name)
                return True
        except WindowsError:
            return False

    def list_values(self, key_path: str) -> Dict[str, Union[str, int, bytes, List[str]]]:
        """List all values in a registry key."""
        values = {}
        try:
            hive, subkey = self._parse_key_path(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        values[name] = value
                        i += 1
                    except WindowsError:
                        break
        except WindowsError:
            pass
        return values

    def list_subkeys(self, key_path: str) -> List[str]:
        """List all subkeys of a registry key."""
        subkeys = []
        try:
            hive, subkey = self._parse_key_path(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(key, i))
                        i += 1
                    except WindowsError:
                        break
        except WindowsError:
            pass
        return subkeys

    def export_key(self, key_path: str, output_file: str) -> bool:
        """Export a registry key to a file."""
        try:
            hive, subkey = self._parse_key_path(key_path)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                data = {
                    'values': self.list_values(key_path),
                    'subkeys': self.list_subkeys(key_path)
                }
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2)
                return True
        except Exception:
            return False

    def import_key(self, input_file: str, key_path: str) -> bool:
        """Import a registry key from a file."""
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
            
            if not self.create_key(key_path):
                return False
            
            for name, value in data['values'].items():
                if not self.write_value(key_path, name, value):
                    return False
            
            for subkey in data['subkeys']:
                if not self.create_key(f"{key_path}\\{subkey}"):
                    return False
            
            return True
        except Exception:
            return False

    def set_persistence(self, name: str, command: str) -> bool:
        """Set persistence via registry."""
        try:
            # Add to Run key
            self.write_value(
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                name,
                command
            )
            
            # Add to RunOnce key
            self.write_value(
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                name,
                command
            )
            
            return True
        except Exception:
            return False

    def remove_persistence(self, name: str) -> bool:
        """Remove persistence from registry."""
        try:
            # Remove from Run key
            self.delete_value(
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                name
            )
            
            # Remove from RunOnce key
            self.delete_value(
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                name
            )
            
            return True
        except Exception:
            return False 