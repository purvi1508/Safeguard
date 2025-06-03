import os
import re
import ast
import math
from typing import List
from safeguard_toolkit.utils.file_utils import REGEX_PATTERNS

class SecretScanner:
    """
    SecretScanner scans files in a project directory or a single file for hardcoded secrets.

    Detection methods:
    - Regex matching for common API keys and credentials
    - Shannon entropy scoring to catch obfuscated secrets
    - AST parsing of Python files for suspicious variable assignments
    """

    SUPPORTED_EXTENSIONS = {'.py', '.env', '.yaml', '.yml', '.json', '.ini', '.toml'}
    ENTROPY_THRESHOLD = 5.0

    def __init__(self, base_path: str, whitelist: List[str] = None):
        self.base_path = base_path
        self.whitelist = whitelist or []
        self.REGEX_PATTERNS = REGEX_PATTERNS

    def scan_path(self, path: str) -> None:
        """
        Scan the given path, which can be a file or a directory.
        """
        if os.path.isfile(path):
            print(f"[INFO] Scanning file: {path}")
            self._scan_file(path)
        elif os.path.isdir(path):
            print(f"[INFO] Scanning directory: {path}")
            self._scan_directory(path)
        else:
            print(f"[ERROR] Path '{path}' is neither a file nor a directory.")

    def _scan_directory(self, directory: str) -> None:
        """
        Recursively scan a directory for secrets.
        """
        for root, _, files in os.walk(directory):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.SUPPORTED_EXTENSIONS:
                    file_path = os.path.join(root, file)
                    self._scan_file(file_path)

    def _scan_file(self, file_path: str) -> None:
        """
        Scan a single file for secrets.
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            print(f"[INFO] Skipping unsupported file: {file_path}")
            return

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                self._scan_lines(file_path, lines)
                if file_path.endswith(".py"):
                    self._scan_ast(file_path, ''.join(lines))
        except Exception as e:
            print(f"[ERROR] Could not read {file_path}: {e}")

    def _scan_lines(self, file_path: str, lines: List[str]) -> None:
        """
        Scan lines of a file using regex and entropy.
        """
        for lineno, line in enumerate(lines, 1):
            if self._is_whitelisted(line):
                continue

            for label, pattern in self.REGEX_PATTERNS.items():
                if re.search(pattern, line):
                    entropy = self._calculate_entropy(line)
                    print(f"[HIGH] {label} in {file_path}:{lineno} | Entropy: {entropy:.2f}")

            if self._calculate_entropy(line) > self.ENTROPY_THRESHOLD:
                print(f"[MEDIUM] High entropy string in {file_path}:{lineno}")

    def _scan_ast(self, file_path: str, source_code: str) -> None:
        """
        Scan Python source for hardcoded secrets in assignments.
        """
        try:
            tree = ast.parse(source_code, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id.lower()
                            if any(k in var_name for k in ["key", "secret", "token", "pwd", "pass"]):
                                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                    entropy = self._calculate_entropy(node.value.value)
                                    print(f"[MEDIUM] Suspect variable '{target.id}' in {file_path}:{node.lineno} | Entropy: {entropy:.2f}")
        except Exception as e:
            print(f"[ERROR] AST parsing failed for {file_path}: {e}")

    def _is_whitelisted(self, line: str) -> bool:
        """
        Check if a line is whitelisted.
        """
        return any(w in line for w in self.whitelist)

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of a string.
        """
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for char in set(data):
            p_x = data.count(char) / length
            entropy -= p_x * math.log2(p_x)
        return entropy
