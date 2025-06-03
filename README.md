# Safeguard Toolkit

Safeguard Toolkit is a Python package for scanning and analyzing project configurations, dependencies, permissions, and secrets to detect security risks, version conflicts, and sensitive data exposure. It supports multiple file types and generates detailed reports to help maintain secure and compliant codebases.

## Features

- **Secrets Scanner:** Detects hardcoded secrets, API keys, tokens, and high-entropy strings in source code and config files.
- **Config Scanner:** Scans `.env`, `.yaml`, `.yml`, and `.json` files for risky configurations and potential secrets.
- **Dependency Checker:** Parses `requirements.txt`, `Pipfile`, and `pyproject.toml` to check for outdated, vulnerable, or license-incompatible dependencies.
- **Permissions Checker:** Identifies files and directories with unsafe permissions (e.g., world-writable, group-writable, or unreadable by owner).
- **Eval/Exec Scanner:** Finds dangerous usage of `eval()`, `exec()`, and similar functions in Python code.

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

### Secrets Scanner

```python
from safeguard_toolkit.core.secrets_scanner import SecretScanner

scanner = SecretScanner(base_path="path/to/scan")
scanner.scan_path("path/to/scan")
# Access scanner.results or implement your own reporting
```

### Config Scanner

```python
from safeguard_toolkit.core.config_scanner import ConfigScanner

scanner = ConfigScanner(path="path/to/configs")
scanner.scan()
issues = scanner.get_issues()
for issue in issues:
    print(issue)
```

### Dependency Checker

```python
from safeguard_toolkit.core.dependency_checker import DependencyChecker

checker = DependencyChecker(path="path/to/project")
checker.run_all_checks()
report = checker.generate_report()
print(report)
```

### Permissions Checker

```python
from safeguard_toolkit.core.permissions_checker import PermissionChecker

checker = PermissionChecker(base_path="path/to/scan")
checker.scan_path("path/to/scan")
unsafe_paths = checker.get_unsafe_paths()
for path, issue in unsafe_paths:
    print(f"{issue}: {path}")
```

### Eval/Exec Scanner

```python
from safeguard_toolkit.core.eval_exec_scanner import EvalExecScanner

scanner = EvalExecScanner()
issues = scanner.scan("path/to/python/files")
for issue in issues:
    print(issue)
```

## Examples

See the [`src/safeguard_toolkit/examples/`](src/safeguard_toolkit/examples/) directory for ready-to-run scripts and sample files for each scanner.

## Requirements

- Python 3.12+
- See [`pyproject.toml`](pyproject.toml) for required packages.


To clean cache and build artifacts:

```sh
make clean
```

## Contributing

Contributions are welcome! Please open issues or pull requests on [GitHub](https://github.com/purvi1508/Safeguard).

## License

MIT License

---

© 2024 Purvi Verma