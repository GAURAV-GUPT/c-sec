import os
import time
import hashlib
import psutil
import json
import streamlit as st
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from crewai import Agent, Task, Crew, Process
from crewai_tools import tool
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

load_dotenv()

# Set page config
st.set_page_config(
    page_title="Cybersecurity Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state
if 'security_events' not in st.session_state:
    st.session_state.security_events = []
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False

# -------------------------------------------------------------------
# Data Models
# -------------------------------------------------------------------
class SecurityEvent:
    def __init__(self, timestamp, script_path, script_hash, process_id, decision, evidence, action_taken):
        self.timestamp = timestamp
        self.script_path = script_path
        self.script_hash = script_hash
        self.process_id = process_id
        self.decision = decision
        self.evidence = evidence
        self.action_taken = action_taken

# -------------------------------------------------------------------
# Enhanced Tools for the Agents
# -------------------------------------------------------------------

@tool("check_against_allowlist")
def check_against_allowlist(script_path: str) -> Dict:
    """
    A tool to check a script's hash and path against a predefined allowlist.
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
        # In Streamlit, we can't actually kill processes for security reasons
        # So we'll simulate this action
        action_summary = f"Would terminate process {process_id} and quarantine file {script_path}"
        
        # Log the action
        st.warning(f"**SECURITY ACTION TAKEN**")
        st.warning(f"Process {process_id} for script '{script_path}' would be killed.")
        st.warning(f"File '{script_path}' would be moved to quarantine.")
        st.warning(f"Reason: {reason}")
        
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
        # Convert to SecurityEvent for storage
        security_event = SecurityEvent(
            timestamp=event_data.get("timestamp", datetime.now()),
            script_path=event_data.get("script_path", ""),
            script_hash=event_data.get("script_hash", ""),
            process_id=event_data.get("process_id"),
            decision=event_data.get("decision", "UNKNOWN"),
            evidence=event_data.get("evidence", ""),
            action_taken=event_data.get("action_taken", "")
        )
        
        # Store in session state for display
        st.session_state.security_events.append(security_event)
        
        # Also print to console for demo purposes
        st.info(f"Logged event: {security_event.script_path} - {security_event.decision}")
        
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
    # For Streamlit, we'll simulate finding scripts rather than actually monitoring
    detected_events = []
    
    # Simulate finding a suspicious file (for demo purposes)
    simulated_files = [
        {"script_path": "/tmp/suspicious_script.py", "process_id": 1234},
        {"script_path": "legitimate_backup.py", "process_id": 5678}
    ]
    
    for file_info in simulated_files:
        detected_events.append({
            "script_path": file_info["script_path"],
            "process_id": file_info["process_id"],
            "detection_time": datetime.now().isoformat()
        })
    
    return detected_events

# -------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------

def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Calculate the hash of a file."""
    # For Streamlit, we'll simulate this since we can't access real files
    fake_hashes = {
        "legitimate_backup.py": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
        "/tmp/suspicious_script.py": "x9y8z7w6v5u4t3s2r1q0p0n9m8l7k6j5i4h3g2f1e0d0c0b0a0"
    }
    return fake_hashes.get(file_path, "unknown_hash_1234567890")

def load_allowlist() -> Dict:
    """Load the allowlist from a file or database."""
    # Default allowlist for demo purposes
    return {
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6": "Legitimate Backup Script",
        "e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4": "Custom Deployment Script",
        "i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4e5f6g7h8": "System Monitoring Agent"
    }

# -------------------------------------------------------------------
# Define our AI Agents
# -------------------------------------------------------------------
llm = ChatOpenAI(model=os.getenv("OPENAI_MODEL", "gpt-3.5-turbo"))

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
# Streamlit UI
# -------------------------------------------------------------------

def main():
    st.title("🛡️ Cybersecurity Threat Monitoring System")
    st.markdown("Real-time monitoring and response to cybersecurity threats using AI agents")
    
    # Sidebar for controls
    with st.sidebar:
        st.header("Controls")
        
        if st.button("Start Monitoring", type="primary"):
            st.session_state.monitoring = True
            st.success("Monitoring started!")
            
        if st.button("Stop Monitoring"):
            st.session_state.monitoring = False
            st.info("Monitoring stopped.")
            
        st.divider()
        
        # Manual script analysis
        st.header("Manual Analysis")
        script_path = st.text_input("Script path to analyze", "/path/to/script.py")
        process_id = st.number_input("Process ID (if known)", min_value=0, value=0)
        
        if st.button("Analyze Script"):
            with st.spinner("Analyzing script..."):
                tasks = create_tasks_for_script(script_path, process_id if process_id > 0 else None)
                
                security_crew = Crew(
                    agents=[monitor_agent, analyst_agent, commander_agent],
                    tasks=tasks,
                    verbose=True,
                    process=Process.sequential
                )
                
                result = security_crew.kickoff()
                st.success("Analysis complete!")
                st.json(result)
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("Security Events")
        
        if st.session_state.security_events:
            for event in st.session_state.security_events:
                with st.expander(f"{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {event.script_path}"):
                    st.write(f"**Decision:** {event.decision}")
                    st.write(f"**Evidence:** {event.evidence}")
                    st.write(f"**Action Taken:** {event.action_taken}")
                    st.write(f"**Hash:** {event.script_hash}")
                    if event.process_id:
                        st.write(f"**Process ID:** {event.process_id}")
        else:
            st.info("No security events logged yet.")
    
    with col2:
        st.header("System Status")
        
        if st.session_state.monitoring:
            st.success("🟢 Monitoring Active")
            
            # Simulate finding new events while monitoring
            if st.button("Simulate Threat Detection"):
                with st.spinner("Processing simulated threat..."):
                    # Simulate finding a suspicious script
                    simulated_script = "/tmp/malicious_script.exe"
                    tasks = create_tasks_for_script(simulated_script, 9999)
                    
                    security_crew = Crew(
                        agents=[monitor_agent, analyst_agent, commander_agent],
                        tasks=tasks,
                        verbose=True,
                        process=Process.sequential
                    )
                    
                    result = security_crew.kickoff()
                    st.rerun()
        else:
            st.warning("🔴 Monitoring Inactive")
        
        st.divider()
        
        st.subheader("Allowlist Contents")
        allowlist = load_allowlist()
        for hash_val, description in allowlist.items():
            st.text(f"{hash_val[:16]}...: {description}")
        
        st.divider()
        
        st.subheader("Agent Status")
        st.success("✅ Monitor Agent: Ready")
        st.success("✅ Analyst Agent: Ready")
        st.success("✅ Commander Agent: Ready")

if __name__ == "__main__":
    main()
