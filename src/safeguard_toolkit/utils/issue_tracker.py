import requests
from packaging.specifiers import SpecifierSet
from packaging import version

SAFETY_DB_URL = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"

def load_safety_db():
    try:
        resp = requests.get(SAFETY_DB_URL, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

def check_vulnerabilities(resolved_versions, db):
    issues = []
    for pkg, ver in resolved_versions.items():
        vulns = db.get(pkg)
        if not vulns:
            continue
        for vuln in vulns:
            for spec in vuln.get("specs", []):
                if version.parse(ver) in SpecifierSet(spec):
                    issues.append(f"Package '{pkg}' version {ver} is vulnerable: {vuln.get('advisory')}")
    return issues

def resolve_versions(deps, metadata_fetcher):
    resolved = {}
    issues = []
    
    for pkg, spec in deps.items():
        data = metadata_fetcher(pkg)
        if not data:
            issues.append(f"Failed to fetch metadata for {pkg}")
            continue
        normalized_spec = ">=0" if spec.strip() == "*" else spec.strip()

        try:
            spec_set = SpecifierSet(normalized_spec)
        except Exception as e:
            issues.append(f"Invalid specifier for {pkg}: '{spec}' ({e})")
            continue

        all_versions = sorted(data["releases"].keys(), key=version.parse, reverse=True)
        compat = [v for v in all_versions if version.parse(v) in spec_set]

        if compat:
            resolved[pkg] = compat[0]
        else:
            issues.append(f"No compatible versions for {pkg} matching '{spec}'")

    return resolved, issues

def check_outdated(resolved_versions, metadata_fetcher):
    issues = []
    for pkg, ver in resolved_versions.items():
        data = metadata_fetcher(pkg)
        if not data:
            continue
        all_versions = sorted(data["releases"].keys(), key=version.parse, reverse=True)
        if version.parse(all_versions[0]) > version.parse(ver):
            issues.append(f"Package '{pkg}' is outdated: {ver} < {all_versions[0]}")
    return issues


class IssueTracker:
    """
    A lightweight utility class for collecting and managing scan issues.

    Stores issues as dictionaries with arbitrary metadata such as:
    - file path
    - line number
    - key/value info
    - error or issue description

    Example:
        tracker = IssueTracker()
        tracker.add(file="config.yaml", line=12, issue="Hardcoded password")
        all_issues = tracker.all()
    """

    def __init__(self):
        """
        Initializes an empty list to store issue entries.
        """
        self._issues = []

    def add(self, **kwargs):
        """
        Adds a new issue to the tracker.

        Args:
            **kwargs: Arbitrary keyword arguments representing issue metadata.
                      Example: file="config.json", line=3, issue="Potential secret"
        """
        self._issues.append(kwargs)

    def all(self):
        """
        Returns:
            list: A list of all tracked issues (as dictionaries).
        """
        return self._issues

    def __len__(self):
        """
        Returns:
            int: The number of issues currently tracked.
        """
        return len(self._issues)
