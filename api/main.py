from agent.llm_client import analyze_vulnerabilities

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os, json
from dotenv import load_dotenv
from mem0 import MemoryClient
from agent.tools_semgrep import run_semgrep, read_file_snippet, remediation_hint


load_dotenv()

#  Initialize FastAPI app\
app = FastAPI(title="AI Code Scanner API", version="1.0")

#  Initialize Mem0 Cloud Client
memory_client = MemoryClient(api_key=os.getenv("MEM0_API_KEY", "m0-your-api-key"))

#  MODELS 
class ScanRequest(BaseModel):
    path: str



@app.get("/")
def home():
    return {"message": " AI Code Scanner API with Mem0 integration active!"}


@app.post("/scan")
async def scan_endpoint(req: ScanRequest):
    """Run a Semgrep scan and store results in Mem0 Cloud."""
    if not os.path.exists(req.path):
        raise HTTPException(status_code=400, detail="Path not found")

    # Run Semgrep and summarize
    scan_result = run_semgrep(req.path)

    if "error" in scan_result:
        raise HTTPException(status_code=500, detail=scan_result["error"])

    #  Always ensure summary key exists
    summary_text = scan_result.get("summary", f"{len(scan_result.get('results', []))} vulnerabilities found")
    results = scan_result.get("results", [])

    #   LLM-based summary
    llm_summary = analyze_vulnerabilities(results)

    stored = 0

    #  vulnerability as a memory in Mem0
    for r in results:
        extra = r.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        file_path = r.get("path", "")
        start_line = r.get("start", {}).get("line", 0)
        end_line = r.get("end", {}).get("line", start_line)
        severity = extra.get("severity", "UNKNOWN")
        message = extra.get("message", "")

        # Build readable content
        code_snippet = read_file_snippet(file_path, start_line, end_line)
        remediation = remediation_hint(r.get("check_id"), message)
        cwe = ", ".join(metadata.get("cwe", []))
        owasp = ", ".join(metadata.get("owasp", []))

        content = (
            f"Security issue detected in {file_path} (lines {start_line}-{end_line}):\n"
            f"{message}\nSeverity: {severity}\nCWE: {cwe}\nOWASP: {owasp}\n"
            f"Remediation: {remediation}\n\nCode Snippet:\n{code_snippet.get('snippet','')}"
        )

        messages = [
            {"role": "user", "content": f"Scan report for {file_path}"},
            {"role": "assistant", "content": content}
        ]

        try:
            memory_client.add(
                messages=messages,
                user_id="ai_code_scanner",
                filters={
                    "repo": os.path.basename(req.path),
                    "file": file_path,
                    "severity": severity,
                    "rule_id": r.get("check_id")
                }
            )
            stored += 1
        except Exception as e:
            print(f" Mem0 storage error: {e}")

    #  similar previous results
    related = []
    try:
        related = memory_client.search(
            query=os.path.basename(req.path),
            user_id="ai_code_scanner",
            filters={"repo": os.path.basename(req.path)},
            limit=3
        )
    except Exception as e:
        print(f" Mem0 search error: {e}")

    # Single final return 
    return {
        "status": "success",
        "repository": os.path.basename(req.path),
        "summary": summary_text,
        "llm_analysis": llm_summary,
        "stored_in_mem0": stored,
        "results": results,
        "related_previous_scans": related
    }
