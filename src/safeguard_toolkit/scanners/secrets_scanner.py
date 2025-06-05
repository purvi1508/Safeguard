import os
from typing import List, Union
from safeguard_toolkit.utils.file_utils import (
    read_lines_from_file,
    scan_lines_with_regex,
    scan_lines_with_entropy,
    REGEX_PATTERNS
)

class SecretScanner:
    SUPPORTED_EXTENSIONS = {'.py', '.env', '.yaml', '.yml', '.json', '.ini', '.toml'}

    def __init__(self, whitelist: List[str] = None):
        self.whitelist = whitelist or []
        self.REGEX_PATTERNS = REGEX_PATTERNS

    def scan(self, input: Union[str, List[str]]) -> None:
        """
        Main method to scan secrets in input which can be:
        - a list of strings (lines)
        - a file path
        - a directory path
        """
        all_findings = []

        if isinstance(input, list):
            findings = self._scan_lines("<string input>", input)
            all_findings.extend(findings)
        elif os.path.isfile(input):
            print(f"[INFO] Scanning file: {input}")
            findings = self._scan_file(input)
            all_findings.extend(findings)
        elif os.path.isdir(input):
            print(f"[INFO] Scanning directory: {input}")
            findings = self._scan_directory(input)
            all_findings.extend(findings)
        else:
            print("[ERROR] Invalid input type. Must be a path or list of strings.")

        return {"findings": all_findings}

    def _scan_directory(self, directory: str) -> None:
        """
        Recursively scan all supported files inside the directory.
        """
        findings = []
        for root, _, files in os.walk(directory):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.SUPPORTED_EXTENSIONS:
                    file_findings = self._scan_file(os.path.join(root, file))
                    findings.extend(file_findings)
        return findings

    def _scan_file(self, file_path: str) -> None:
        """
        Scan a single file for secrets:
        - Read file lines
        - Scan lines with regex and entropy methods
        - If Python file, scan AST for suspicious assignments
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            print(f"[INFO] Skipping unsupported file: {file_path}")
            return []

        lines = read_lines_from_file(file_path)
        findings = self._scan_lines(file_path, lines)

        return findings

    def _scan_lines(self, source: str, lines: List[str]) -> None:
        """
        Scan the given lines for secrets:
        - Using regex patterns to find known secret patterns
        - Using entropy checks to find suspiciously random strings
        """
        regex_findings = scan_lines_with_regex(lines, self.REGEX_PATTERNS, self.whitelist)
        entropy_findings = scan_lines_with_entropy(lines, self.whitelist,5.0)
        return regex_findings + entropy_findings
