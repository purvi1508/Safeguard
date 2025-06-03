from safeguard_toolkit.core.secrets_scanner import SecretScanner

def main():
    base_path = "./examples/secrets_scanner"
    scanner = SecretScanner(base_path=base_path)
    scanner.scan_path(base_path)

if __name__ == "__main__":
    main()