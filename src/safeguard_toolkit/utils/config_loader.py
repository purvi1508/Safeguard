import os
import json
import yaml
import toml
from packaging.requirements import Requirement

def load_config_file(path):
    """
    Loads configuration data from a supported config file.

    Supports:
    - JSON (.json)
    - YAML (.yaml, .yml)
    - dotenv (.env)

    Args:
        path (str): The path to the configuration file.

    Returns:
        dict: Parsed configuration data as a dictionary.
              Returns an empty dict if unsupported or parse fails.
    """
    ext = os.path.splitext(path)[1].lower()

    with open(path, "r", encoding="utf-8") as f:
        if ext in [".yaml", ".yml"]:
            # Load YAML safely into a Python dict
            return yaml.safe_load(f)
        elif ext == ".json":
            # Load JSON into a Python dict
            return json.load(f)
        elif ext == ".env" or os.path.basename(path) == ".env":
            # Parse key-value pairs from a .env file
            return parse_dotenv(f)

    # Unsupported file types
    return {}

def parse_dotenv(file_obj):
    """
    Parses a .env-style file (key=value format).

    Ignores comments and empty lines.

    Args:
        file_obj (file object): Open file object for .env file.

    Returns:
        dict: Parsed key-value pairs from the .env file.
    """
    result = {}

    for line in file_obj:
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#") or "=" not in line:
            continue

        # Split into key and value
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('\'"')  # Remove quotes around values if present

        result[key] = val

    return result


def parse_requirements_txt(filepath):
    deps = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                req = Requirement(line)
                deps[req.name.lower()] = str(req.specifier) or ">=0"
            except Exception:
                parts = line.split("==")
                if len(parts) == 2:
                    deps[parts[0].lower()] = f"=={parts[1]}"
                else:
                    deps[line.lower()] = ">=0"
    return deps

def parse_pipfile(filepath):
    deps = {}
    pipfile_data = toml.load(filepath)
    for section in ("packages", "dev-packages"):
        pkgs = pipfile_data.get(section, {})
        for pkg, spec in pkgs.items():
            version_spec = spec.get("version", ">=0") if isinstance(spec, dict) else spec or ">=0"
            deps[pkg.lower()] = version_spec
    return deps

def parse_pyproject_toml(filepath):
    deps = {}
    data = toml.load(filepath)
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for pkg, spec in poetry_deps.items():
        if pkg == "python":
            continue
        version_spec = spec.get("version", ">=0") if isinstance(spec, dict) else spec or ">=0"
        deps[pkg.lower()] = version_spec
    return deps
