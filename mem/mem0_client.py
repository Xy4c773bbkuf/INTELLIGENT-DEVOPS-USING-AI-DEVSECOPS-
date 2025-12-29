# mem0_client.py

from mem0 import MemoryClient
from dotenv import load_dotenv
import os
import json

#  Load environment variables
load_dotenv()

#  Initialize global Mem0 client
memory_client = MemoryClient(api_key=os.getenv("MEM0_API_KEY", "m0-your-api-key"))


#  Add Memories to Mem0
def store_vulnerabilities_in_mem0(results, repository: str):
    """
    Stores Semgrep vulnerability findings in Mem0 Cloud.
    Each finding is stored as a separate memory with filters.
    """
    try:
        for issue in results:
            file_path = issue.get("file", "")
            severity = issue.get("severity", "UNKNOWN")
            rule_id = issue.get("rule_id", "")
            message = issue.get("message", "")
            remediation = issue.get("remediation", "")

            #  Required: messages format
            messages = [
                {"role": "user", "content": f"Scan report for {file_path}"},
                {"role": "assistant", "content": f"{message}\nRemediation: {remediation}"}
            ]

            #  Add to Mem0
            memory_client.add(
                messages=messages,
                user_id="ai_code_scanner",
                filters={
                    "repo": repository,
                    "file": file_path,
                    "severity": severity,
                    "rule_id": rule_id
                }
            )
        print(f" Stored {len(results)} vulnerabilities in Mem0 successfully.")
    except Exception as e:
        print(f" Failed to store vulnerabilities in Mem0: {e}")


#  Search Memories in Mem0
def search_related_memories(repo_name: str, limit: int = 3):
    """
    Retrieve related vulnerabilities for the same repository.
    """
    try:
        results = memory_client.search(
            query=repo_name,
            user_id="ai_code_scanner",
            filters={"repo": repo_name},
            limit=limit
        )
        return results
    except Exception as e:
        print(f" Search error: {e}")
        return []
