# 🔐 Safeguard Toolkit – ConfigScanner Module

## Overview

The **ConfigScanner** module is part of the Safeguard Toolkit, a modular Python library designed to help developers identify risky configuration settings and security misconfigurations across project files.

It intelligently parses and analyzes configuration files including:

- `.env`
- `.yaml` / `.yml`
- `.json`

Using a recursive scanner and pattern-based detection, it provides a structured way to flag:

- Risky default configurations (e.g., `DEBUG=true`, `allow_all_origins=true`)
- Misconfigurations in deeply nested files

---

## Key Features

- Supports directory or single-file scanning
- Flags risky configuration values based on known heuristics
- Modular utility-based architecture for easy extension
- Tracks issues with contextual metadata (file, key, line, etc.)
- Gracefully handles parse errors in config files

---

## 🧩 Architecture

- **ConfigScanner Class**
  - Entry point for scanning.
  - Collects `.env`, `.yaml`, `.yml`, and `.json` files using `get_files_by_extension`.
  - Uses `load_config_file` to load each file safely.
  - Sends parsed data to `scan_nested_dict` for deep inspection.
  - Issues are collected and managed by `IssueTracker`.

- **load_config_file(path) → dict**
  - Parses `.env`, `.yaml`, `.json` files into Python dictionaries.
  - Falls back to empty dict if format is unsupported or invalid.

- **scan_nested_dict(data, path, issue_tracker)**
  - Recursively traverses key-value structures.
  - Uses dot-notation (e.g., `database.credentials.password`) for nested keys.
  - Delegates each flat key-value pair to `scan_key_value`.

- **scan_key_value(path, key, val, issue_tracker, lineno=None)**
  - Matches key and val against:
    - `RISKY_CONFIGS`: Dict of known risky key-value combinations.
  - Stores flagged results in `IssueTracker`.

- **IssueTracker**
  - Manages a list of detected issues.
  - Provides methods: `add()`, `all()`, `__len__()`.

---

## 🔍 What It Detects

| Risk Type      | Description                                      | Example                        |
|----------------|--------------------------------------------------|--------------------------------|
| ⚠️ Risky Values| Unsafe config values in production contexts      | `DEBUG=true`, `allow_all_origins=true` |
| 💥 Parse Errors| Invalid YAML/JSON/.env syntax that prevents safe loading | Broken formatting or malformed values |

---
