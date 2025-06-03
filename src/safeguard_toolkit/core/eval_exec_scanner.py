import os
import ast
from typing import List, Tuple


class EvalExecScanner(ast.NodeVisitor):
    """
    Scans Python files for dangerous usage of eval(), exec(), compile() in exec mode,
    and other risky dynamic code execution functions.

    Usage:
        scanner = EvalExecScanner()
        results = scanner.scan('path/to/project_or_file')
    """

    def __init__(self):
        # List of tuples: (filepath, lineno, col_offset, code_snippet, issue)
        self.issues: List[Tuple[str, int, int, str, str]] = []

    def visit_Call(self, node: ast.Call):
        """
        Visit function call nodes and check for dangerous functions.
        """
        # Check for eval()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == "eval":
                self._report_issue(node, "Use of eval() detected")

            elif func_name == "exec":  # Python 2 style exec function (rare in Python 3)
                self._report_issue(node, "Use of exec() detected")

            elif func_name == "execfile":  # Python 2 legacy
                self._report_issue(node, "Use of execfile() detected")

            elif func_name == "compile":
                # Check if mode argument is 'exec'
                if len(node.args) >= 3:
                    mode_arg = node.args[2]
                    if isinstance(mode_arg, ast.Str) and mode_arg.s == "exec":
                        self._report_issue(node, "Use of compile() with exec mode detected")

        self.generic_visit(node)

    def _report_issue(self, node: ast.Call, issue: str):
        """
        Record an issue with location and code snippet.

        Args:
            node (ast.Call): The AST node where issue detected.
            issue (str): Description of the issue.
        """
        filename = getattr(node, '_filename', '<unknown>')
        lineno = node.lineno
        col_offset = node.col_offset

        code_line = self._get_source_line(filename, lineno)

        self.issues.append((filename, lineno, col_offset, code_line.strip(), issue))

    @staticmethod
    def _get_source_line(filename: str, lineno: int) -> str:
        """
        Retrieve a specific line from a file.

        Args:
            filename (str): Path to source file.
            lineno (int): Line number (1-based).

        Returns:
            str: The source code line or empty string if not found.
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if 0 < lineno <= len(lines):
                    return lines[lineno - 1]
        except Exception:
            pass
        return ""

    def scan_file(self, filepath: str) -> List[Tuple[str, int, int, str, str]]:
        """
        Scan a single Python file for dangerous eval/exec usage.

        Args:
            filepath (str): Path to Python file.

        Returns:
            List[Tuple[str, int, int, str, str]]: List of detected issues.
        """
        self.issues.clear()

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source = f.read()
        except Exception as e:
            print(f"[ERROR] Could not read file {filepath}: {e}")
            return []

        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as e:
            print(f"[WARNING] Syntax error in {filepath}: {e}")
            return []

        # Attach filename to nodes for reporting
        for node in ast.walk(tree):
            setattr(node, '_filename', filepath)

        self.visit(tree)
        return self.issues.copy()

    def scan_directory(self, root_path: str) -> List[Tuple[str, int, int, str, str]]:
        """
        Recursively scan a directory for Python files and check for issues.

        Args:
            root_path (str): Root directory to scan.

        Returns:
            List[Tuple[str, int, int, str, str]]: List of detected issues.
        """
        all_issues = []

        for dirpath, _, filenames in os.walk(root_path):
            for fname in filenames:
                if fname.endswith('.py'):
                    full_path = os.path.join(dirpath, fname)
                    issues = self.scan_file(full_path)
                    all_issues.extend(issues)

        return all_issues

    def scan(self, path: str) -> List[Tuple[str, int, int, str, str]]:
        """
        Scan a path which can be either a file or a directory.

        Args:
            path (str): Path to a Python file or directory.

        Returns:
            List[Tuple[str, int, int, str, str]]: List of detected issues.
        """
        if os.path.isfile(path):
            return self.scan_file(path)
        elif os.path.isdir(path):
            return self.scan_directory(path)
        else:
            print(f"[ERROR] Path '{path}' is neither a file nor a directory.")
            return []
