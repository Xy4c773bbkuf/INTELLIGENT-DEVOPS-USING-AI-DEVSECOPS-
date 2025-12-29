

import subprocess
import json
import os
from typing import Dict, Any


# Semgrep Runner 
def run_semgrep(target_dir: str, rule_dir: str = "rules") -> Dict[str, Any]:
    """
    Run Semgrep CLI on target_dir using rules in rule_dir.
    Returns parsed JSON output.
    """
    try:
        # Normalize and print the path for safety
        target_dir = os.path.abspath(target_dir).replace("\\", "/")
        print(f" Scanning directory: {target_dir}")

        # Always use built-in rules to avoid missing "rules/" folder error
        cmd = ["semgrep", "--config=auto", "--json", target_dir]
        print(f" Running Semgrep command: {' '.join(cmd)}")

        # Force UTF-8 to avoid encoding errors
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env
        )

        print(f"STDOUT:\n{proc.stdout[:300]}")
        print(f"STDERR:\n{proc.stderr[:300]}")

        if proc.returncode not in (0, 1):
            return {"error": f"Semgrep failed (code {proc.returncode}): {proc.stderr}"}

        parsed = json.loads(proc.stdout)
        return parsed

    except json.JSONDecodeError:
        return {"error": "Failed to parse Semgrep JSON output"}
    except FileNotFoundError:
        return {"error": "Semgrep executable not found. Please install with 'pip install semgrep'."}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


#  Helper: Code Snippet Extraction 
def read_file_snippet(path: str, start_line: int, end_line: int, context: int = 3):
    """
    Extract code snippet around vulnerable section.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, start_line - context - 1)
        end = min(len(lines), end_line + context)
        snippet = "".join(lines[start:end])
        return {
            "context_before": context,
            "context_after": context,
            "snippet": snippet,
            "total_lines": len(lines)
        }
    except Exception as e:
        return {"snippet": f"(Could not read file: {e})"}


#  Helper: Remediation Hints
def remediation_hint(rule_id: str, message: str) -> str:
    """
    Generate remediation suggestions for a given rule or message.
    """
    rule_id = (rule_id or "").lower()
    msg = (message or "").lower()

    if "eval" in rule_id or "eval" in msg:
        return "Avoid using eval()/exec(); prefer safer parsing or whitelisting."
    if "sql" in rule_id or "sql" in msg:
        return "Use parameterized queries or ORM to prevent SQL injection."
    if "os.system" in msg or "subprocess" in msg or "shell" in msg:
        return "Avoid shell=True or direct command execution with user input."
    if "xss" in msg or "template" in msg:
        return "Escape user inputs or use frameworks with built-in escaping."
    if "path" in msg or "traversal" in msg:
        return "Sanitize filenames; use secure upload paths."
    if "hardcoded" in msg or "password" in msg:
        return "Never hardcode credentials; use environment variables or vaults."
    return "Review this code for general security best practices."
