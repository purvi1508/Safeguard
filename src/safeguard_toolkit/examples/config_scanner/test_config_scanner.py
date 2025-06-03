import os
from safeguard_toolkit.core.config_scanner import ConfigScanner

def test_config_scanner():
    base_path = "./examples/config_scanner"
    scanner = ConfigScanner(path=base_path)
    scanner.scan()
    issues = scanner.get_issues()

    for issue in issues:
        print(f"File: {issue.get('file')}")
        print(f"Line: {issue.get('line')}")
        print(f"Key: {issue.get('key')}")
        print(f"Value: {issue.get('value')}")
        print(f"Issue: {issue.get('issue')}")
        print("-" * 40)

if __name__ == "__main__":
    test_config_scanner()
