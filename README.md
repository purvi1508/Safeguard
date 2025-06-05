# Safeguard Toolkit

Safeguard Toolkit is a comprehensive Python package for scanning and analyzing project configurations, dependencies, permissions, and secrets to detect security risks, version conflicts, and sensitive data exposure. It supports multiple file types and generates detailed reports to help maintain secure and compliant codebases.

---

## 🚀 Features

- **Secrets Scanner:** Detects hardcoded secrets, API keys, tokens, and high-entropy strings in source code and config files.
- **Config Scanner:** Scans `.env`, `.yaml`, `.yml`, and `.json` files for risky configurations and potential secrets.
- **Dependency Checker:** Parses `requirements.txt`, `Pipfile`, and `pyproject.toml` to check for outdated, vulnerable, or license-incompatible dependencies.
- **Permissions Checker:** Identifies files and directories with unsafe permissions (e.g., world-writable, group-writable, or unreadable by owner).
- **Modular Design:** Each scanner can be used independently or as part of a full project scan.
- **Extensible:** Easily add new scanners or customize existing ones.

---

## Installation

Install the latest release from PyPI:

```sh
pip install safeguard_toolkit
```

Or, for development:

```sh
git clone https://github.com/purvi1508/Safeguard.git
cd Safeguard
pip install -e .
```

## Usage

Each scanner can be run independently. Example usage for each module is provided in the `src/safeguard_toolkit/examples/` directory.

### Base Scanner

```python
from safeguard_toolkit.core.base_scanner import ScanManager
import json


scan_path = "examples/dependency_checker_project"
enabled_scans = ['secrets', 'permissions']
whitelist = ['EXEMPT_VAR']

scanner = ScanManager(path=scan_path, enable=enabled_scans, whitelist=whitelist)
results = scanner.run()

print(json.dumps(results, indent=2))
```

### Secrets Scanner

```python
from safeguard_toolkit.scanners.secrets_scanner import SecretScanner

scanner = SecretScanner(whitelist=["SAFE_TOKEN"])
scanner.scan("path/to/scan")
```

### Config Scanner

```python
from safeguard_toolkit.scanners.config_scanner import ConfigScanner

scanner = ConfigScanner(path="path/to/configs")
scanner.scan()
issues = scanner.get_issues()
for issue in issues:
    print(issue)
```

### Dependency Checker

```python
from safeguard_toolkit.scanners.dependency_checker import DependencyChecker

checker = DependencyChecker(path="path/to/project")
checker.run_all_checks()
report = checker.generate_report()
print(report)
```

### Permissions Checker

```python
from safeguard_toolkit.scanners.permissions_checker import PermissionChecker

checker = PermissionChecker(base_path="path/to/scan")
checker.scan_path("path/to/scan")
unsafe_paths = checker.get_unsafe_paths()
for path, issue in unsafe_paths:
    print(f"{issue}: {path}")
```

## Examples

📚 Examples
Ready-to-run Jupyter notebooks and sample projects are available in src/safeguard_toolkit/examples/:

test_secrets_scanner.ipynb
test_config_scanner.ipynb
test_dependency_checker.ipynb
test_permission_checker.ipynb
test_base_scanner.ipynb
Each notebook demonstrates the scanner's features with real files.

## Requirements

- Python 3.12+
- See [`pyproject.toml`](pyproject.toml) for required packages.


To clean cache and build artifacts:

```sh
make clean
```

## License

MIT License

---

© 2024 Purvi Verma
