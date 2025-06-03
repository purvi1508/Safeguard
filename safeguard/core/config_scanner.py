import os
import re
import json
import yaml
from safeguard.utils.file_utils import get_files_by_extension , RISKY_CONFIGS, SECRET_PATTERNS

class ConfigScanner:
    """
    Scans configuration files for common misconfigurations
    and sensitive secrets.
    """

    def __init__(self, path="."):
        if os.path.isdir(path):
            self.config_paths = get_files_by_extension(path, [".env", ".yaml", ".yml", ".json"])
        elif os.path.isfile(path):
            self.config_paths = [path]
        else:
            raise ValueError(f"Path '{path}' is neither a file nor a directory")

        self.issues = []
        self.RISKY_CONFIGS = RISKY_CONFIGS
        self.SECRET_PATTERNS = SECRET_PATTERNS

    def scan(self):
        for path in self.config_paths:
            if not os.path.exists(path):
                continue
            ext = os.path.splitext(path)[1].lower()
            try:
                if ext == ".env" or os.path.basename(path) == ".env":
                    self._scan_env(path)
                elif ext in [".yaml", ".yml"]:
                    self._scan_yaml(path)
                elif ext == ".json":
                    self._scan_json(path)
            except Exception as e:
                self.issues.append({
                    "file": path,
                    "error": f"Failed to parse file: {e}"
                })
                
    def _scan_env(self, path):
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('\'"')
                self._check_key_value(path, lineno, key, val)

    def _scan_yaml(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                self._recursive_scan(path, data)

    def _scan_json(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                self._recursive_scan(path, data)

    def _recursive_scan(self, file_path, data, parent_key=""):
        for key, val in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            if isinstance(val, dict):
                self._recursive_scan(file_path, val, full_key)
            else:
                self._check_key_value(file_path, None, full_key, str(val))

    def _check_key_value(self, file_path, lineno, key, val):
        key_lower = key.lower()
        val_lower = val.lower()

        for risky_key, risky_vals in self.RISKY_CONFIGS.items():
            if risky_key.lower() == key_lower:
                if risky_vals is None or val_lower in risky_vals:
                    self.issues.append({
                        "file": file_path,
                        "line": lineno,
                        "key": key,
                        "value": val,
                        "issue": f"Risky configuration: {key}={val}"
                    })

        for pattern in self.SECRET_PATTERNS:
            if pattern.search(key):
                if len(val) > 6:
                    self.issues.append({
                        "file": file_path,
                        "line": lineno,
                        "key": key,
                        "value": val if len(val) < 30 else val[:30] + "...",
                        "issue": "Potential secret detected"
                    })

    def get_issues(self):
        return self.issues