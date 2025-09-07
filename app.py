import os
import time
import hashlib
import psutil
import json
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Dict, List, Optional
from pydantic import BaseModel

from crewai import Agent, Task, Crew, Process
from crewai_tools import tool
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------------------------
# Data Models
# -------------------------------------------------------------------
class SecurityEvent(BaseModel):
    timestamp: datetime
    script_path: str
    script_hash: str
    process_id: Optional[int] = None
    decision: str
    evidence: str
    action_taken: str

# -------------------------------------------------------------------
# Enhanced Tools for the Agents
# -------------------------------------------------------------------

@tool("check_against_allowlist")
def check_against_allowlist(script_path: str) -> Dict:
    """
    A tool to check a script's hash and path against a predefined allowlist.
    Now with real hash calculation and external allowlist source.
    """
    try:
        # Calculate real hash of the file
        file_hash = calculate_file_hash(script_path)
        
        # Load allowlist from external source (file, DB, API, etc.)
        allowed_scripts = load_allowlist()
        
        # Check if the hash is in the allowlist
        if file_hash in allowed_scripts:
            return {
                "status": "ALLOW",
                "message": f"Script '{script_path}' (hash: {file_hash}) is trusted: {allowed_scripts[file_hash]}",
                "hash": file_hash
            }
        else:
            return {
                "status": "BLOCK",
                "message": f"Script '{script_path}' (hash: {file_hash}) is NOT in the allowlist!",
                "hash": file_hash
            }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Error checking allowlist for {script_path}: {str(e)}"
        }

@tool("kill_malicious_process")
def kill_malicious_process(script_path: str, process_id: int, reason: str) -> Dict:
    """
    A tool to kill a process and quarantine a file.
    """
    try:
        # Terminate the process
        process = psutil.Process(process_id)
        process.terminate()
        
        # Wait a moment, then kill if still running
        try:
            process.wait(timeout=3)
        except psutil.TimeoutExpired:
            process.kill()
        
        # Quarantine the file
        quarantine_path = quarantine_file(script_path)
        
        action_summary = f"Terminated process {process_id} and quarantined file to {quarantine_path}"
        
        # Log the action
        print(f"\n  **SECURITY ACTION TAKEN**  ")
        print(f"Process {process_id} for script '{script_path}' has been killed.")
        print(f"File '{script_path}' has been moved to quarantine at {quarantine_path}.")
        print(f"Reason: {reason}")
        
        return {
            "status": "SUCCESS",
            "message": action_summary
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Failed to neutralize threat: {str(e)}"
        }

@tool("log_event_to_siem")
def log_event_to_siem(event_data: Dict) -> Dict:
    """
    A tool to log an event to a SIEM system.
    """
    try:
        # Convert to SecurityEvent model for validation
        security_event = SecurityEvent(**event_data)
        
        # In a real implementation, this would send to Splunk, Elasticsearch, etc.
        timestamp = security_event.timestamp.isoformat()
        log_entry = {
            "timestamp": timestamp,
            "script_path": security_event.script_path,
            "script_hash": security_event.script_hash,
            "process_id": security_event.process_id,
            "decision": security_event.decision,
            "evidence": security_event.evidence,
            "action_taken": security_event.action_taken
        }
        
        # Write to local log file (replace with API call to SIEM in production)
        with open("security_logs.jsonl", "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
        
        # Also print to console for demo purposes
        print(f"  Logged to SIEM: {log_entry}")
        
        return {
            "status": "SUCCESS",
            "message": f"Event logged for {security_event.script_path}"
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Failed to log event: {str(e)}"
        }

@tool("monitor_file_system")
def monitor_file_system() -> List[Dict]:
    """
    A tool to monitor the file system for new script executions.
    Returns a list of detected events.
    """
    # This would be implemented with inotify/fsevents on a real system
    # For this POC, we'll simulate finding scripts in common directories
    detected_events = []
    
    # Common directories to monitor
    monitor_dirs = [
        "/tmp",
        "/var/tmp",
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/.local/share"),
    ]
    
    # Common script extensions
    script_extensions = [".py", ".sh", ".ps1", ".exe", ".js", ".bat", ".cmd"]
    
    for directory in monitor_dirs:
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    if any(file.endswith(ext) for ext in script_extensions):
                        file_path = os.path.join(root, file)
                        # Check if file is currently executing
                        process_info = find_process_by_file(file_path)
                        
                        if process_info:
                            detected_events.append({
                                "script_path": file_path,
                                "process_id": process_info["pid"],
                                "detection_time": datetime.now().isoformat()
                            })
    
    return detected_events

# -------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------

def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Calculate the hash of a file."""
    hash_func = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def load_allowlist() -> Dict:
    """Load the allowlist from a file or database."""
    # In a real implementation, this would come from a secure source
    allowlist_path = "allowlist.json"
    if os.path.exists(allowlist_path):
        with open(allowlist_path, "r") as f:
            return json.load(f)
    
    # Default allowlist for demo purposes
    return {
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6": "Legitimate Backup Script",
        "e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4": "Custom Deployment Script",
        "i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4e5f6g7h8": "System Monitoring Agent"
    }

def quarantine_file(file_path: str) -> str:
    """Move a file to quarantine."""
    quarantine_dir = "/var/quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    
    filename = os.path.basename(file_path)
    quarantine_path = os.path.join(quarantine_dir, f"{int(time.time())}_{filename}")
    
    os.rename(file_path, quarantine_path)
    return quarantine_path

def find_process_by_file(file_path: str) -> Optional[Dict]:
    """Find if a process is running with the given file."""
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            if proc.info['exe'] and os.path.samefile(proc.info['exe'], file_path):
                return {"pid": proc.info['pid'], "name": proc.info['name']}
            
            # Check command line arguments
            if proc.info['cmdline']:
                for cmd in proc.info['cmdline']:
                    if os.path.exists(cmd) and os.path.samefile(cmd, file_path):
                        return {"pid": proc.info['pid'], "name": proc.info['name']}
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
            continue
    
    return None

# -------------------------------------------------------------------
# File System Monitor Class
# -------------------------------------------------------------------

class ScriptExecutionHandler(FileSystemEventHandler):
    """Watchdog event handler for detecting script executions."""
    
    def __init__(self, crew):
        self.crew = crew
        self.script_extensions = [".py", ".sh", ".ps1", ".exe", ".js", ".bat", ".cmd"]
    
    def on_created(self, event):
        if not event.is_directory:
            file_ext = os.path.splitext(event.src_path)[1].lower()
            if file_ext in self.script_extensions:
                print(f"Detected new script: {event.src_path}")
                # In a real implementation, we would trigger the crew here
                # For this POC, we'll just log it
                log_event_to_siem({
                    "timestamp": datetime.now(),
                    "script_path": event.src_path,
                    "script_hash": "pending",
                    "process_id": None,
                    "decision": "PENDING",
                    "evidence": "New script detected",
                    "action_taken": "Logged for analysis"
                })

# -------------------------------------------------------------------
# Define our AI Agents
# -------------------------------------------------------------------
llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-4o"))

# Agent 1: The Monitor
monitor_agent = Agent(
    role="Server Security Monitor",
    goal="Continuously watch for new script executions and processes on the server and report them for analysis.",
    backstory="You are a vigilant monitoring agent deployed on every server in the infrastructure. Your only job is to observe and report.",
    tools=[monitor_file_system, log_event_to_siem],
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

def create_tasks_for_script(script_path, process_id=None):
    """Create tasks for analyzing a specific script."""
    monitor_task = Task(
        description=f"Monitor the server. You have detected a new script execution: '{script_path}'. This needs immediate analysis. First, log that you have detected it.",
        expected_output="A confirmation that the event has been logged and passed to the analyst.",
        agent=monitor_agent,
    )

    analysis_task = Task(
        description=f"Analyze the detected script '{script_path}'. Use your tool to check it against the allowlist. Make a definitive decision: if it's not on the list, the decision is KILL. If it is on the list, the decision is ALLOW. Log your decision and the evidence.",
        expected_output="A clear decision of either ALLOW or KILL for the script, along with the evidence from the allowlist check.",
        agent=analyst_agent,
    )

    response_task = Task(
        description="Based on the Analyst's decision, take action. If the decision was KILL, use your tool to neutralize the threat. If the decision was ALLOW, simply log that no action was taken. Always log the action you performed.",
        expected_output="Confirmation that the necessary enforcement action (or inaction) has been completed.",
        agent=commander_agent,
    )
    
    return [monitor_task, analysis_task, response_task]

# -------------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------------

def main():
    # Start file system monitoring
    event_handler = ScriptExecutionHandler(None)
    observer = Observer()
    
    # Watch common directories
    watch_dirs = [
        "/tmp",
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/.local/share"),
    ]
    
    for directory in watch_dirs:
        if os.path.exists(directory):
            observer.schedule(event_handler, directory, recursive=True)
    
    observer.start()
    print(f"Started monitoring directories: {watch_dirs}")
    
    try:
        # Simulate initial detection for demo purposes
        script_to_analyze = "hacker_ransomware.exe"
        
        print(f"  Simulating detection of script: {script_to_analyze}")
        print("="*50)
        
        # Create tasks for the detected script
        tasks = create_tasks_for_script(script_to_analyze, process_id=1234)
        
        # Assemble the crew and run
        security_crew = Crew(
            agents=[monitor_agent, analyst_agent, commander_agent],
            tasks=tasks,
            verbose=2,
            process=Process.sequential
        )
        
        result = security_crew.kickoff()
        
        print("\n" + "="*50)
        print("  Simulation Complete!")
        print(f"Final result: {result}")
        
        # Keep running to monitor for real events
        print("\nContinuing to monitor for real file system events...")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()

if __name__ == "__main__":
    main()
