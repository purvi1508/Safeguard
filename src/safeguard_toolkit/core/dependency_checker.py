import os
import json
import toml
import subprocess
import requests
from packaging import version
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
from collections import defaultdict

class DependencyChecker:
    """
    Advanced Dependency Checker:
    - Parses requirements.txt, Pipfile, pyproject.toml
    - Resolves dependency graph (transitive)
    - Checks compatibility and version conflicts
    - Detects outdated packages
    - Checks known vulnerabilities (via Safety DB)
    - Checks licenses (basic check)
    - Supports caching of PyPI metadata
    - Outputs detailed report

    Can accept a single file path or a directory path.
    """

    PYPI_API_URL = "https://pypi.org/pypi/{package}/json"
    SAFETY_DB_URL = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"

    def __init__(self, path="."):
        self.path = path
        self.dependencies = {}  # package_name -> version specifier (e.g. >=1.0,<2.0)
        self.resolved_versions = {}  # package_name -> resolved version string
        self.transitive_deps = defaultdict(set)  # package -> set of dependencies
        self.vulnerabilities_db = None
        self.cache = {}
        self.issues = []
        self.licenses = {}

    def load_dependencies(self):
        if os.path.isdir(self.path):
            self._load_from_directory()
        elif os.path.isfile(self.path):
            self._load_from_file(self.path)
        else:
            self.issues.append(f"Path does not exist: {self.path}")

    def _load_from_directory(self):
        if not os.path.isdir(self.path):
            self.issues.append(f"Provided path is not a directory: {self.path}")
            return

        filenames = os.listdir(self.path)
        print(f"Scanning directory: {self.path}")
        print(f"Files found: {filenames}")

        file_map = {
            "requirements.txt": self._parse_requirements_txt,
            "pipfile": self._parse_pipfile,
            "pyproject.toml": self._parse_pyproject_toml,
        }

        for fname, parser_func in file_map.items():
            matched_files = [f for f in filenames if f.lower() == fname]
            if matched_files:
                full_path = os.path.join(self.path, matched_files[0])
                print(f"Parsing {full_path} with {parser_func.__name__}")
                parser_func(full_path)

    def _load_from_file(self, filepath):
        fname = os.path.basename(filepath).lower()
        print(f"Loading single file: {filepath}")

        if fname == "requirements.txt":
            self._parse_requirements_txt(filepath)
        elif fname == "pipfile":
            self._parse_pipfile(filepath)
        elif fname == "pyproject.toml":
            self._parse_pyproject_toml(filepath)
        else:
            self.issues.append(f"Unsupported file type: {filepath}")

    def _parse_requirements_txt(self, filepath):
        if not os.path.exists(filepath):
            return
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    req = Requirement(line)
                    self.dependencies[req.name.lower()] = str(req.specifier) or ">=0"
                except Exception:
                    parts = line.split("==")
                    if len(parts) == 2:
                        self.dependencies[parts[0].lower()] = f"=={parts[1]}"
                    else:
                        self.dependencies[line.lower()] = ">=0"

    def _parse_pipfile(self, filepath):
        if not os.path.exists(filepath):
            return
        try:
            pipfile_data = toml.load(filepath)
            for section in ("packages", "dev-packages"):
                pkgs = pipfile_data.get(section, {})
                for pkg, spec in pkgs.items():
                    if isinstance(spec, dict):
                        version_spec = spec.get("version", ">=0")
                    else:
                        version_spec = spec or ">=0"
                    self.dependencies[pkg.lower()] = version_spec
        except Exception as e:
            self.issues.append(f"Failed to parse Pipfile: {e}")

    def _parse_pyproject_toml(self, filepath):
        if not os.path.exists(filepath):
            return
        try:
            data = toml.load(filepath)
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for pkg, spec in poetry_deps.items():
                if pkg == "python":
                    continue
                if isinstance(spec, dict):
                    version_spec = spec.get("version", ">=0")
                else:
                    version_spec = spec or ">=0"
                self.dependencies[pkg.lower()] = version_spec
        except Exception as e:
            self.issues.append(f"Failed to parse pyproject.toml: {e}")

    def fetch_pypi_metadata(self, package_name):
        if package_name in self.cache:
            return self.cache[package_name]
        url = self.PYPI_API_URL.format(package=package_name)
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                self.cache[package_name] = data
                return data
        except Exception:
            pass
        return None

    def resolve_versions(self):
        """
        For each dependency, resolve latest compatible version.
        """
        for pkg, spec in self.dependencies.items():
            data = self.fetch_pypi_metadata(pkg)
            if not data:
                self.issues.append(f"Failed to fetch PyPI metadata for {pkg}")
                continue
            all_versions = sorted(data["releases"].keys(), key=version.parse, reverse=True)
            spec_set = SpecifierSet(spec)
            compatible_versions = [v for v in all_versions if version.parse(v) in spec_set]
            if compatible_versions:
                self.resolved_versions[pkg] = compatible_versions[0]
            else:
                self.issues.append(f"No compatible versions found for {pkg} matching '{spec}'")

    def build_transitive_dependencies(self):
        """
        Build transitive dependency graph by parsing metadata 'requires_dist'
        """
        for pkg, ver in self.resolved_versions.items():
            data = self.fetch_pypi_metadata(pkg)
            if not data:
                continue
            releases = data.get("releases", {})
            if ver not in releases:
                continue
            files = releases.get(ver)
            # find metadata requires_dist
            requires_dist = data.get("info", {}).get("requires_dist", [])
            for dep in requires_dist or []:
                # Example format: "requests>=2.0; python_version >= '3.4'"
                dep_req = dep.split(";")[0].strip()
                if dep_req:
                    dep_name = dep_req.split()[0]
                    self.transitive_deps[pkg].add(dep_name.lower())

    def check_outdated(self):
        """
        Check which packages have newer versions than resolved
        """
        for pkg, ver in self.resolved_versions.items():
            data = self.fetch_pypi_metadata(pkg)
            if not data:
                continue
            all_versions = sorted(data["releases"].keys(), key=version.parse, reverse=True)
            if all_versions and version.parse(all_versions[0]) > version.parse(ver):
                self.issues.append(f"Package '{pkg}' is outdated: {ver} < {all_versions[0]}")

    def load_vulnerabilities_db(self):
        """
        Load vulnerabilities from Safety DB (can cache locally for performance)
        """
        try:
            resp = requests.get(self.SAFETY_DB_URL, timeout=5)
            if resp.status_code == 200:
                self.vulnerabilities_db = resp.json()
        except Exception:
            self.issues.append("Failed to load vulnerabilities DB")

    def check_vulnerabilities(self):
        """
        Check resolved versions against vulnerability database
        """
        if self.vulnerabilities_db is None:
            self.load_vulnerabilities_db()
        if not self.vulnerabilities_db:
            return

        for pkg, ver in self.resolved_versions.items():
            vulns = self.vulnerabilities_db.get(pkg)
            if not vulns:
                continue
            for vuln in vulns:
                # vuln contains 'specs' list with version ranges
                for spec in vuln.get("specs", []):
                    spec_set = SpecifierSet(spec)
                    if version.parse(ver) in spec_set:
                        self.issues.append(f"Package '{pkg}' version {ver} is vulnerable: {vuln.get('advisory')}")

    def check_licenses(self):
        """
        Simple license check - flag uncommon or disallowed licenses
        """
        disallowed = {"GPL", "AGPL", "LGPL"}  # example disallowed licenses
        for pkg in self.resolved_versions:
            data = self.fetch_pypi_metadata(pkg)
            if not data:
                continue
            license_str = data.get("info", {}).get("license", "").upper()
            self.licenses[pkg] = license_str
            for dis in disallowed:
                if dis in license_str:
                    self.issues.append(f"Package '{pkg}' has disallowed license: {license_str}")

    def generate_report(self):
        """
        Generate a detailed report dictionary
        """
        return {
            "dependencies": self.dependencies,
            "resolved_versions": self.resolved_versions,
            "transitive_dependencies": {k: list(v) for k, v in self.transitive_deps.items()},
            "issues": self.issues,
            "licenses": self.licenses
        }

    def run_all_checks(self):
        self.load_dependencies()
        self.resolve_versions()
        self.build_transitive_dependencies()
        self.check_outdated()
        self.check_vulnerabilities()
        self.check_licenses()


