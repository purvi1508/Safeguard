from collections import defaultdict
from os import path, listdir
from safeguard_toolkit.utils.config_loader import (
    parse_requirements_txt,
    parse_pipfile,
    parse_pyproject_toml
)
from safeguard_toolkit.utils.file_utils import fetch_pypi_metadata
from safeguard_toolkit.utils.issue_tracker import (
    resolve_versions,
    check_outdated,
    load_safety_db,
    check_vulnerabilities
)
from safeguard_toolkit.utils.licences import check_licenses


class DependencyChecker:
    def __init__(self, path="."):
        self.path = path
        self.dependencies = {}
        self.resolved_versions = {}
        self.transitive_deps = defaultdict(set)
        self.licenses = {}
        self.issues = []
        self.cache = {}

    def _get_metadata(self, pkg):
        return fetch_pypi_metadata(pkg, self.cache)

    def load_dependencies(self):
        if path.isdir(self.path):
            files = listdir(self.path)
            for fname in files:
                full_path = path.join(self.path, fname)
                self._parse_if_supported(fname.lower(), full_path)

        elif path.isfile(self.path):
            fname = path.basename(self.path).lower()
            self._parse_if_supported(fname, self.path)

        else:
            self.issues.append(f"Unsupported path: {self.path}")

    def _parse_if_supported(self, fname, full_path):
        if fname == "requirements.txt":
            self.dependencies.update(parse_requirements_txt(full_path))
        elif fname == "pipfile":
            self.dependencies.update(parse_pipfile(full_path))
        elif fname == "pyproject.toml":
            self.dependencies.update(parse_pyproject_toml(full_path))
        else:
            self.issues.append(f"Unsupported file type: {fname}")

    def run_all_checks(self):
        self.load_dependencies()

        self.resolved_versions, issues = resolve_versions(
            self.dependencies, self._get_metadata
        )
        self.issues.extend(issues)

        self.issues.extend(check_outdated(self.resolved_versions, self._get_metadata))

        db = load_safety_db()
        if db:
            self.issues.extend(check_vulnerabilities(self.resolved_versions, db))

        self.licenses, license_issues = check_licenses(
            self.resolved_versions, self._get_metadata
        )
        self.issues.extend(license_issues)

    def generate_report(self):
        return {
            "dependencies": self.dependencies,
            "resolved_versions": self.resolved_versions,
            "transitive_dependencies": {k: list(v) for k, v in self.transitive_deps.items()},
            "issues": self.issues,
            "licenses": self.licenses
        }
