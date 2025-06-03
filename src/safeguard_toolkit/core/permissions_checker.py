import os
import stat
from typing import List, Tuple

class PermissionChecker:
    def __init__(self, base_path: str, check_group_writable: bool = True):
        self.base_path = base_path
        self.check_group_writable = check_group_writable

    def scan(self) -> None:
        print(f"Scanning base_path recursively: {self.base_path}")
        for root, dirs, files in os.walk(self.base_path):
            for d in dirs:
                path = os.path.join(root, d)
                self._check_path(path, is_dir=True)
            for f in files:
                path = os.path.join(root, f)
                self._check_path(path, is_dir=False)

    def scan_path(self, path: str) -> None:
        print(f"Scanning path: {path}")
        if os.path.isfile(path):
            print("Detected a file.")
            self._check_path(path, is_dir=False)
        elif os.path.isdir(path):
            print("Detected a directory.")
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    dir_path = os.path.join(root, d)
                    self._check_path(dir_path, is_dir=True)
                for f in files:
                    file_path = os.path.join(root, f)
                    self._check_path(file_path, is_dir=False)
        else:
            print(f"[ERROR] Path '{path}' is neither a file nor a directory.")

    def _check_path(self, path: str, is_dir: bool) -> None:
        print(f"Checking {'directory' if is_dir else 'file'}: {path}")
        try:
            st = os.lstat(path)
        except Exception as e:
            print(f"[ERROR] Could not stat {path}: {e}")
            return

        mode = st.st_mode

        if not (mode & stat.S_IRUSR):
            print(f"[WARNING] Owner has NO read permission on {'directory' if is_dir else 'file'}: {path}")

        if mode & stat.S_IWOTH:
            print(f"[CRITICAL] World-writable {'directory' if is_dir else 'file'}: {path}")

        if self.check_group_writable and (mode & stat.S_IWGRP):
            print(f"[WARNING] Group-writable {'directory' if is_dir else 'file'}: {path}")

    def get_unsafe_paths(self) -> List[Tuple[str, str]]:
        unsafe = []
        for root, dirs, files in os.walk(self.base_path):
            for d in dirs:
                path = os.path.join(root, d)
                issue = self._get_issue(path, is_dir=True)
                if issue:
                    unsafe.append((path, issue))
            for f in files:
                path = os.path.join(root, f)
                issue = self._get_issue(path, is_dir=False)
                if issue:
                    unsafe.append((path, issue))
        return unsafe

    def _get_issue(self, path: str, is_dir: bool) -> str:
        try:
            st = os.lstat(path)
        except Exception:
            return ""

        mode = st.st_mode

        if not (mode & stat.S_IRUSR):
            return "Owner has NO read permission"
        if mode & stat.S_IWOTH:
            return "World-writable permission"
        if self.check_group_writable and (mode & stat.S_IWGRP):
            return "Group-writable permission"

        return ""

