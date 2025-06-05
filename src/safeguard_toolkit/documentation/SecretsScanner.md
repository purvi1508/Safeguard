# SecretScanner – Documentation

The `SecretScanner` class is part of the Safeguard Toolkit and is designed to detect secrets such as API keys, passwords, tokens, and high-entropy strings in source code and configuration files. It supports scanning individual files, directories, or lists of strings.

---

## Features

- **Supported File Types:**  
  `.py`, `.env`, `.yaml`, `.yml`, `.json`, `.ini`, `.toml`

- **Detection Methods:**  
  - Regex-based detection for known secret patterns  
  - Entropy-based detection for suspiciously random strings

- **Recursive Directory Scanning:**  
  Scans all supported files in a directory tree

- **Whitelist Support:**  
  Ignore specific keys or patterns during scanning

---

## Usage

### Core Functionalities

#### SecretScanner(whitelist: List[str] = None)

- **Parameters:**  
  `whitelist` — Optional list of keys or patterns to ignore during scanning.

#### scan(input: Union[str, List[str]]) -> dict

- **Parameters:**  
  - `input`:  
    - Path to a file (string)  
    - Path to a directory (string)  
    - List of strings (lines)

- **Returns:**  
  A dictionary with a `"findings"` key containing a list of detected secrets.

---

## Use Cases

- The SecretScanner automates scanning files and directories to detect potential secrets based on regex patterns and entropy analysis.
- It helps identify hardcoded secrets or suspicious random strings that resemble secrets.
Developers can provide a whitelist of known safe patterns to reduce false positives.
- It supports common config file formats (.env, .yaml, .json, .ini, etc.) and source code files (.py).
- It can be integrated into automated tools to prevent secret leaks before code merges or deployments.
