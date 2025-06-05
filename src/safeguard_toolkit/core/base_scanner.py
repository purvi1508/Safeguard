import os
from typing import List, Dict, Union

from safeguard_toolkit.scanners.secrets_scanner import SecretScanner
from safeguard_toolkit.scanners.permissions_checker import PermissionChecker
from safeguard_toolkit.scanners.config_scanner import ConfigScanner 
from safeguard_toolkit.scanners.dependency_checker import DependencyChecker 

class ScanManager:
    def __init__(
        self,
        path: str,
        enable: List[str] = None,
        whitelist: List[str] = None,
        entropy_threshold: float = 5.0
    ):
        self.path = path
        self.whitelist = whitelist or []
        self.entropy_threshold = entropy_threshold
        self.enabled_scanners = enable or ['secrets', 'permissions']  # Defaults
        self.findings: Dict[str, List[str]] = {}

    def run(self) -> Dict[str, List[str]]:
        """
        Runs all enabled scanners and collects findings in a dictionary.
        """
        if not os.path.exists(self.path):
            print(f"[ERROR] Path does not exist: {self.path}")
            return {}

        if 'secrets' in self.enabled_scanners:
            print("[INFO] Running SecretScanner...")
            secret_scanner = SecretScanner(whitelist=self.whitelist)
            result = secret_scanner.scan(self.path)
            self.findings['secrets'] = result.get("findings", [])

        if 'permissions' in self.enabled_scanners:
            print("[INFO] Running PermissionChecker...")
            perm_checker = PermissionChecker(self.path)
            issues = perm_checker.get_unsafe_paths()
            self.findings['permissions'] = [f"{path}: {issue}" for path, issue in issues]

        if 'config' in self.enabled_scanners:
            print("[INFO] Running ConfigScanner...")
            config_scanner = ConfigScanner(self.path)
            config_scanner.scan()
            config_issues=config_scanner.get_issues()
            self.findings['config'] = config_issues

        if 'dependencies' in self.enabled_scanners:
            print("[INFO] Running DependencyChecker...")
            dep_checker = DependencyChecker(self.path)
            dep_checker.run_all_checks()
            report = dep_checker.generate_report()
            self.findings['dependencies'] = report

        return self.findings
