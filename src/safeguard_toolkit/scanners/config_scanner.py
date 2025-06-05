import os
import os.path as osp
from typing import List, Union, Optional

from safeguard_toolkit.utils.file_utils import get_files_by_extension
from safeguard_toolkit.utils.config_loader import load_config_file
from safeguard_toolkit.utils.key_value_utils import scan_nested_dict
from safeguard_toolkit.utils.issue_tracker import IssueTracker


class ConfigScanner:
    """
    Scans configuration files (.env, .yaml, .yml, .json) in a given path
    to detect risky configuration settings and misconfigurations.

    Secret detection is intentionally excluded and handled by a dedicated SecretScanner.

    Uses modular utility components for parsing, scanning, and issue tracking.
    """

    def __init__(self, path: str = ".") -> None:
        """
        Initializes the scanner for a given path.

        Args:
            path (str): Path to a file or directory to scan.
                        Defaults to current directory.

        Raises:
            ValueError: If the provided path is not a file or directory.
        """
        if os.path.isdir(path):
            self.config_paths = get_files_by_extension(path, [".env", ".yaml", ".yml", ".json"])
        elif os.path.isfile(path):
            self.config_paths = [path]
        else:
            raise ValueError(f"Path '{path}' is neither a file nor a directory")
        self.issues = IssueTracker()

    def scan(self) -> None:
        """
        Runs the scanner on all discovered config files.

        Uses file extension to determine the appropriate loader and
        dispatches scanning to a nested dictionary scanner that
        checks for risky configuration values.

        Note:
            Secrets scanning is not performed here.
        """
        for path in self.config_paths:
            try:
                config_data = load_config_file(path)

                if isinstance(config_data, dict):
                    scan_nested_dict(config_data, path, self.issues)

                elif isinstance(config_data, list):
                    for item in config_data:
                        if isinstance(item, dict):
                            scan_nested_dict(item, path, self.issues)

            except Exception as e:
                self.issues.add(
                    file=path,
                    error=f"Failed to parse file: {e}"
                )

    def get_issues(self) -> List[dict]:
        """
        Returns a list of all detected risky configuration issues.

        Returns:
            List[dict]: List of issues, each represented as a dictionary.
        """
        return self.issues.all()
