from safeguard_toolkit.utils.file_utils import RISKY_CONFIGS, SECRET_PATTERNS

def scan_nested_dict(data, file_path, issue_tracker, parent_key=""):
    """
    Recursively scans nested dictionaries (from YAML/JSON files) 
    to detect risky configurations.

    Args:
        data (dict): The dictionary structure to scan.
        file_path (str): Path of the file being scanned.
        issue_tracker (IssueTracker): Instance to store discovered issues.
        parent_key (str, optional): Dot-notated prefix for nested keys.
    """
    for key, val in data.items():
        full_key = f"{parent_key}.{key}" if parent_key else key

        if isinstance(val, dict):
            scan_nested_dict(val, file_path, issue_tracker, full_key)
        else:
            scan_key_value(file_path, full_key, str(val), issue_tracker)


def scan_key_value(file_path, key, val, issue_tracker, lineno=None):
    """
    Evaluates a single key-value pair for risky configurations.

    Args:
        file_path (str): Path of the file where the key-value was found.
        key (str): Configuration key (can be dot-notated for nesting).
        val (str): The corresponding value.
        issue_tracker (IssueTracker): Collector for any discovered issues.
        lineno (int, optional): Line number (if available, e.g., from .env).
    """
    key_lower = key.lower()
    val_lower = val.lower()

    for risky_key, risky_vals in RISKY_CONFIGS.items():
        if risky_key.lower() == key_lower:
            if risky_vals is None or val_lower in risky_vals:
                issue_tracker.add(
                    file=file_path,
                    line=lineno,
                    key=key,
                    value=val,
                    issue=f"Risky configuration: {key}={val}"
                )
