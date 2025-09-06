import os
import time
from datetime import datetime
from crewai import Agent, Task, Crew, Process
from crewai_tools import tool
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------------------------
# Tools for the Agents
# These tools represent the "actions" the agents can take.
# In a real system, these would call actual system APIs or commands.
# -------------------------------------------------------------------

@tool("check_against_allowlist")
def check_against_allowlist(script_path: str) -> str:
    """
    A tool to simulate checking a script's hash and path against a predefined allowlist.
    In reality, this would query a database or a CMDB.
    """
    # Simulated Allowlist Database (Hash -> Name)
    allowed_scripts = {
        "a1b2c3d4": "Legitimate Backup Script",
        "e5f6g7h8": "Custom Deployment Script",
        "i9j0k1l2": "System Monitoring Agent"
    }
    
    # Simulate calculating a hash (in reality, use hashlib.sha256)
    simulated_hash = simulate_hash_calculation(script_path)
    
    # Check if the hash is in the allowlist
    if simulated_hash in allowed_scripts:
        return f"ALLOW: Script '{script_path}' (hash: {simulated_hash}) is trusted: {allowed_scripts[simulated_hash]}"
    else:
        return f"BLOCK: Script '{script_path}' (hash: {simulated_hash}) is NOT in the allowlist!"

@tool("kill_malicious_process")
def kill_malicious_process(script_path: str, reason: str) -> str:
    """
    A tool to simulate the action of killing a process and quarantining a file.
    In reality, this would call os.kill or a subprocess to call 'kill -9 [pid]'.
    """
    # Simulate the action
    print(f"\n  **SECURITY ACTION TAKEN**  ")
    print(f"Process for script '{script_path}' has been killed.")
    print(f"File '{script_path}' has been moved to quarantine.")
    print(f"Reason: {reason}")
    # In reality: os.remove(script_path) or shutil.move to quarantine
    return f"Successfully neutralized threat from {script_path}"

@tool("log_event_to_siem")
def log_event_to_siem(script_path: str, decision: str, evidence: str):
    """
    A tool to simulate logging an event to a central SIEM system for auditing.
    """
    timestamp = datetime.now().isoformat()
    log_entry = f"{timestamp} | Script: {script_path} | Decision: {decision} | Evidence: {evidence}\n"
    
    # Simulate writing to a log file (in reality, send to Splunk/Sentinel/Elastic)
    with open("security_logs.txt", "a") as log_file:
        log_file.write(log_entry)
    print(f"  Logged to SIEM: {log_entry}")
    return f"Event logged for {script_path}"

# Helper function for the simulation
def simulate_hash_calculation(path):
    """Simulates a hash based on the filename for this demo."""
    fake_hashes = {
        "backup.py": "a1b2c3d4",
        "deploy_app.sh": "e5f6g7h8",
        "monitor.py": "i9j0k1l2",
        "hacker_ransomware.exe": "x9y8z7w6", # This is malicious
        "suspicious_script.ps1": "malicious_hash_123" # This is malicious
    }
    return fake_hashes.get(path, "unknown_hash")

# -------------------------------------------------------------------
# Define our AI Agents
# -------------------------------------------------------------------
llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"))

# Agent 1: The Monitor
monitor_agent = Agent(
    role="Server Security Monitor",
    goal="Continuously watch for new script executions and processes on the server and report them for analysis.",
    backstory="You are a vigilant monitoring agent deployed on every server in the infrastructure. Your only job is to observe and report.",
    tools=[log_event_to_siem], # Can log what it finds
    verbose=True,
    llm=llm
)

# Agent 2: The Analyst (The Decider)
analyst_agent = Agent(
    role="Senior Security Analyst",
    goal="Determine if a reported script or process is malicious by checking it against the strict allowlist. Your decision is final.",
    backstory="You are the core intelligence of the security system. You have encyclopedic knowledge of all approved company software and scripts. You are paranoid and trust nothing outside the allowlist.",
    tools=[check_against_allowlist, log_event_to_siem],
    verbose=True,
    llm=llm
)

# Agent 3: The Commander (The Enforcer)
commander_agent = Agent(
    role="Security Incident Responder",
    goal="Execute the commands from the Senior Security Analyst to KILL processes and quarantine files to protect the server.",
    backstory="You are the automated response system. You act swiftly and decisively on the Analyst's instructions to neutralize threats before they can cause damage.",
    tools=[kill_malicious_process, log_event_to_siem],
    verbose=True,
    llm=llm
)

# -------------------------------------------------------------------
# Define Tasks for the Agents
# -------------------------------------------------------------------

# Simulate a monitoring event. In reality, this would be triggered by an OS hook.
script_to_analyze = "hacker_ransomware.exe" # Change this to 'backup.py' to see an ALLOW outcome.

monitor_task = Task(
    description=f"Monitor the server. You have detected a new script execution: '{script_to_analyze}'. This needs immediate analysis. First, log that you have detected it.",
    expected_output="A confirmation that the event has been logged and passed to the analyst.",
    agent=monitor_agent,
)

analysis_task = Task(
    description=f"Analyze the detected script '{script_to_analyze}'. Use your tool to check it against the allowlist. Make a definitive decision: if it's not on the list, the decision is KILL. If it is on the list, the decision is ALLOW. Log your decision and the evidence.",
    expected_output="A clear decision of either ALLOW or KILL for the script, along with the evidence from the allowlist check.",
    agent=analyst_agent,
)

response_task = Task(
    description="Based on the Analyst's decision, take action. If the decision was KILL, use your tool to neutralize the threat. If the decision was ALLOW, simply log that no action was taken. Always log the action you performed.",
    expected_output="Confirmation that the necessary enforcement action (or inaction) has been completed.",
    agent=commander_agent,
)

# -------------------------------------------------------------------
# Assemble the Crew and Run the Simulation
# -------------------------------------------------------------------
security_crew = Crew(
    agents=[monitor_agent, analyst_agent, commander_agent],
    tasks=[monitor_task, analysis_task, response_task],
    verbose=2, # Set to 2 for detailed execution logs
    process=Process.sequential # Tasks are executed one after another
)

print(f"  Simulating detection of script: {script_to_analyze}")
print("="*50)

result = security_crew.kickoff()

print("\n" + "="*50)
print("  Simulation Complete!")
print(f"Final result: {result}")
