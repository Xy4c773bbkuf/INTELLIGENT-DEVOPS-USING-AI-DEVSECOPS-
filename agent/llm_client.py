
from typing import List, Dict
import json


from langchain_openai import ChatOpenAI  
from langchain_core.messages import SystemMessage, HumanMessage

def analyze_vulnerabilities(findings: List[Dict], model: str = "gpt-4o-mini") -> str:
    """
    Summarizes and prioritizes vulnerabilities using an LLM.
    findings: list of Semgrep result dicts
    """
    if not findings:
        return "No vulnerabilities found."

    # Compact summary of raw findings
    short_summary = json.dumps(findings[:10], indent=2)[:4000]

    # Initialize LLM
    llm = ChatOpenAI(model=model, temperature=0.4) 

    system_prompt = SystemMessage(
        content=(
            "You are ai code scanner agent. "
            "Given Semgrep data, produce a summary report. "
            "how can we fix these vulnerabilities."
        )
    )

    user_prompt = HumanMessage(
        content=f"Here are the Semgrep findings:\n{short_summary}\n\nSummarize and rank by criticality."
    )

    response = llm.invoke([system_prompt, user_prompt])
    return response.content
