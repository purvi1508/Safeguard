import os
from safeguard_toolkit.core.eval_exec_scanner import EvalExecScanner

def test_eval_exec_scanner():
    base_path = "./examples/eval_exec_scanner"
    scanner = EvalExecScanner()  
    issues = scanner.scan(base_path)
    
    for issue in issues:
        print(issue)

if __name__ == "__main__":
    test_eval_exec_scanner()
