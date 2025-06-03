import os
from safeguard.core.permissions_checker import PermissionChecker

def test_permissions_checker():
    base_path = "./examples/permissions_checker"
    checker = PermissionChecker(base_path)
    checker.scan_path(base_path)
    unsafe_paths = checker.get_unsafe_paths()
    
    for path, issue in unsafe_paths:
        print(f"{issue}: {path}")

if __name__ == "__main__":
    test_permissions_checker()
