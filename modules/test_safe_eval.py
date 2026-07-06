"""
test_safe_eval.py
Unit tests to verify safe evaluation of playbook conditions and defense against malicious injection.
"""

import sys
import os

# Add parent directory to sys.path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.safe_eval import safe_eval_condition, SecurityException

def run_tests():
    context = {
        "severity": "critical",
        "abuse_score": 85,
        "is_internal": True,
        "indicator": "198.51.100.42"
    }

    tests = [
        # (condition, expected_result, should_raise_exception)
        ("severity == 'critical'", True, False),
        ("severity == 'medium'", False, False),
        ("severity != 'low'", True, False),
        ("abuse_score >= 75", True, False),
        ("abuse_score < 50", False, False),
        ("severity in ['critical', 'medium']", True, False),
        ("severity not in ['low', 'medium']", True, False),
        ("is_internal == True", True, False),
        ("not is_internal", False, False),
        ("severity == 'critical' and abuse_score > 80", True, False),
        ("severity == 'critical' or abuse_score < 10", True, False),
        ("undefined_variable == None", True, False),
        
        # Security injection tests (should raise SecurityException)
        ("__import__('os').system('echo pwned')", None, True),
        ("severity.startswith('crit')", None, True),
        ("open('/etc/passwd').read()", None, True),
        ("eval('1+1')", None, True),
    ]

    passed = 0
    failed = 0

    for i, (cond, expected, should_err) in enumerate(tests, 1):
        try:
            res = safe_eval_condition(cond, context)
            if should_err:
                print(f"[-] Test {i} FAILED: Expected security exception for '{cond}' but got result {res}")
                failed += 1
            elif res == expected:
                print(f"[+] Test {i} PASSED: '{cond}' -> {res}")
                passed += 1
            else:
                print(f"[-] Test {i} FAILED: '{cond}' -> expected {expected}, got {res}")
                failed += 1
        except SecurityException as e:
            if should_err:
                print(f"[+] Test {i} PASSED (Security Blocked): '{cond}' -> {type(e).__name__}: {e}")
                passed += 1
            else:
                print(f"[-] Test {i} FAILED: Unexpected SecurityException for '{cond}': {e}")
                failed += 1
        except Exception as e:
            print(f"[-] Test {i} ERROR: Unexpected exception for '{cond}': {e}")
            failed += 1

    print(f"\nSummary: {passed} passed, {failed} failed")
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
