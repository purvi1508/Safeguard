# Dependency Checker – Overview and Design Rationale

## 📘 Introduction

The **Dependency Checker** is a modular Python tool designed to analyze, resolve, and validate Python project dependencies. It supports multiple dependency formats and checks for issues such as version conflicts, outdated packages, known vulnerabilities, and disallowed licenses.

The tool is intended to be extendable, testable, and reusable across CLI tools, security scanners, and CI/CD pipelines.

---

## ⚙️ Core Functionalities

### 1. **Dependency Parsing**
The tool supports:
- `requirements.txt`
- `Pipfile`
- `pyproject.toml`

Each of these formats is parsed to extract a mapping of packages to their version specifiers (e.g., `requests >=2.0,<3.0`).

### 2. **Metadata Resolution**
It uses the **PyPI API** to fetch metadata for each dependency:
- Available versions
- Release dates
- License information
- Metadata such as `requires_dist` for transitive dependencies

A caching mechanism is employed to reduce redundant API calls.

### 3. **Version Resolution**
For each declared dependency, the tool:
- Fetches all available versions from PyPI.
- Filters them based on the specified version constraints.
- Selects the **latest compatible version**.

This helps simulate real-world package installation behavior (`pip`-like resolution).

### 4. **Transitive Dependency Mapping**
Based on the `requires_dist` metadata, the tool maps first-level dependencies to their second-level (transitive) dependencies. This helps understand the full dependency graph and identify potential nested risks.

### 5. **Outdated Package Detection**
The tool identifies whether a newer version exists for each resolved dependency. If so, it raises a warning such as:
Package 'requests' is outdated: 2.25.1 < 2.31.0


This is useful for maintaining up-to-date dependencies and avoiding security risks.

### 6. **Vulnerability Scanning**
It integrates with the [Safety DB](https://github.com/pyupio/safety-db) to:
- Load a curated list of known vulnerable package versions.
- Match resolved versions against these known CVEs.
- Flag insecure versions with a detailed advisory.

### 7. **License Compliance**
Each package’s license metadata is extracted and checked against a **disallowed license list** (e.g., `GPL`, `AGPL`). These licenses may pose legal or business risks.

---

## 🔍 Use Cases

- **Security Audits**: Identify vulnerable or risky dependencies.
- **CI/CD Pipelines**: Enforce dependency policies automatically.
- **Software Bill of Materials (SBOM)**: Generate a snapshot of all dependencies and versions.
- **Legal Review**: Ensure compliance with software licensing requirements.

