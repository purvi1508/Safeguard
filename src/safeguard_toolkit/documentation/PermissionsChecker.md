# PermissionChecker – Documentation

The `PermissionChecker` class helps to scan files and directories recursively to identify potential permission issues such as missing owner read permissions, world-writable, or group-writable permissions. This is useful for improving system security by ensuring that sensitive files and directories have proper access controls.

---

## Features

- Recursively scans directories and files starting from a base path.
- Detects the following permission issues:
  - Owner lacks read permission.
  - World-writable files or directories.
  - Group-writable files or directories (optional check).
- Provides both interactive scanning with console output and programmatic retrieval of unsafe paths.

---

## Class 

### `PermissionChecker(base_path: str, check_group_writable: bool = True)`

Creates a permission checker for the given base path.

- `base_path`: The root directory path to scan recursively.
- `check_group_writable`: Whether to check for group-writable permissions (default: `True`).

---
# Practical Applications of PermissionChecker

- **Server Security Auditing**  
  Scan servers to find world-writable or unreadable files and directories, preventing unauthorized access.

- **CI/CD Pipeline Security**  
  Automate permission checks before deployment to catch misconfigurations early.

- **Compliance and Auditing**  
  Support security audits by generating reports of unsafe file permissions for standards like PCI-DSS or GDPR.

- **Development Environment Checks**  
  Ensure sensitive files in development do not have overly permissive permissions, promoting secure practices.

---

*PermissionChecker helps maintain secure file permissions to reduce risk and improve system security.*
