import os
from safeguard.core.dependency_checker import DependencyChecker

def test_dependency_checker():
    base_path = "./examples/dependency_checker"
    checker = DependencyChecker(project_dir=base_path)
    checker.run_all_checks()
    results = checker.generate_report()
    print("Issues:", results["issues"])
    print("Dependencies:", results["dependencies"])
    print("Resolved Versions:", results["resolved_versions"])

if __name__ == "__main__":
    test_dependency_checker()
