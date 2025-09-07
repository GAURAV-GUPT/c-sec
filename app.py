import os
import streamlit as st
from datetime import datetime
import json
from openai import OpenAI
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

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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
# Helper Functions
# -------------------------------------------------------------------

def check_against_allowlist(script_path: str) -> Dict:
    """
    Check a script against a predefined allowlist.
    """
    # Simulated allowlist for demo purposes
    allowed_scripts = {
        "legitimate_backup.py": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
        "deploy_app.sh": "e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4",
        "monitor.py": "i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2c3d4e5f6g7h8"
    }
    
    # Simulated hash calculation
    script_name = os.path.basename(script_path)
    script_hash = allowed_scripts.get(script_name, "unknown_hash_1234567890")
    
    if script_name in allowed_scripts:
        return {
            "status": "ALLOW",
            "message": f"Script '{script_path}' (hash: {script_hash}) is trusted",
            "hash": script_hash
        }
    else:
        return {
            "status": "BLOCK",
            "message": f"Script '{script_path}' (hash: {script_hash}) is NOT in the allowlist!",
            "hash": script_hash
        }

def log_event_to_siem(event_data: Dict) -> Dict:
    """
    Log an event to the SIEM system.
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

def analyze_with_ai(script_path, script_info):
    """
    Use OpenAI to analyze the script and make a decision.
    """
    prompt = f"""
    You are a cybersecurity analyst. Analyze the following script and determine if it should be allowed or blocked.
    
    Script Path: {script_path}
    Script Info: {json.dumps(script_info, indent=2)}
    
    Consider:
    1. Is this script in our allowlist?
    2. Does the script path look suspicious?
    3. Based on the hash, is this a known malicious script?
    
    Provide your decision (ALLOW or BLOCK) and a brief explanation.
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst specializing in threat detection."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150
        )
        
        analysis = response.choices[0].message.content
        return analysis
    except Exception as e:
        return f"Error analyzing script: {str(e)}"

def monitor_agent(script_path, process_id=None):
    """
    Simulate the monitor agent.
    """
    st.info(f"Monitor: Detected script execution - {script_path}")
    
    # Log the detection
    log_event_to_siem({
        "script_path": script_path,
        "process_id": process_id,
        "decision": "DETECTED",
        "evidence": "Script execution detected",
        "action_taken": "Passed to analyst for review"
    })
    
    return {
        "status": "SUCCESS",
        "message": f"Script {script_path} detected and logged"
    }

def analyst_agent(script_path, process_id=None):
    """
    Simulate the analyst agent.
    """
    st.info(f"Analyst: Analyzing script - {script_path}")
    
    # Check against allowlist
    allowlist_result = check_against_allowlist(script_path)
    
    # Use AI for additional analysis
    ai_analysis = analyze_with_ai(script_path, allowlist_result)
    
    # Make decision
    if allowlist_result["status"] == "ALLOW":
        decision = "ALLOW"
        evidence = f"Script is in allowlist: {allowlist_result['message']}"
    else:
        decision = "BLOCK"
        evidence = f"Script not in allowlist. AI analysis: {ai_analysis}"
    
    # Log the decision
    log_event_to_siem({
        "script_path": script_path,
        "script_hash": allowlist_result.get("hash", "unknown"),
        "process_id": process_id,
        "decision": decision,
        "evidence": evidence,
        "action_taken": "Decision made"
    })
    
    return {
        "status": "SUCCESS",
        "decision": decision,
        "evidence": evidence,
        "message": f"Analysis complete for {script_path}"
    }

def commander_agent(script_path, decision, evidence, process_id=None):
    """
    Simulate the commander agent.
    """
    st.info(f"Commander: Executing decision for script - {script_path}")
    
    if decision == "BLOCK":
        action = "Would terminate process and quarantine file"
        st.warning(f"**SECURITY ACTION** Would block script: {script_path}")
    else:
        action = "No action needed - script is allowed"
        st.success(f"Script allowed: {script_path}")
    
    # Log the action
    log_event_to_siem({
        "script_path": script_path,
        "process_id": process_id,
        "decision": decision,
        "evidence": evidence,
        "action_taken": action
    })
    
    return {
        "status": "SUCCESS",
        "message": f"Action completed for {script_path}: {action}"
    }

def process_script(script_path, process_id=None):
    """
    Process a script through all agents.
    """
    # Monitor agent
    monitor_result = monitor_agent(script_path, process_id)
    if monitor_result["status"] != "SUCCESS":
        return monitor_result
    
    # Analyst agent
    analyst_result = analyst_agent(script_path, process_id)
    if analyst_result["status"] != "SUCCESS":
        return analyst_result
    
    # Commander agent
    commander_result = commander_agent(
        script_path, 
        analyst_result["decision"], 
        analyst_result["evidence"],
        process_id
    )
    
    return commander_result

# -------------------------------------------------------------------
# Streamlit UI
# -------------------------------------------------------------------

def main():
    st.title("🛡️ Cybersecurity Threat Monitoring System")
    st.markdown("Real-time monitoring and response to cybersecurity threats using AI agents")
    
    # Sidebar for controls
    with st.sidebar:
        st.header("Controls")
        
        if st.button("Simulate Legitimate Script"):
            result = process_script("legitimate_backup.py", 1234)
            st.success("Simulation complete!")
        
        if st.button("Simulate Malicious Script"):
            result = process_script("malicious_script.exe", 9999)
            st.success("Simulation complete!")
            
        st.divider()
        
        # Manual script analysis
        st.header("Manual Analysis")
        script_path = st.text_input("Script path to analyze", "suspicious_script.py")
        process_id = st.number_input("Process ID (if known)", min_value=0, value=0)
        
        if st.button("Analyze Script"):
            with st.spinner("Analyzing script..."):
                result = process_script(
                    script_path, 
                    process_id if process_id > 0 else None
                )
                st.success("Analysis complete!")
    
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
        
        st.subheader("Allowlist Contents")
        allowlist = {
            "legitimate_backup.py": "Legitimate Backup Script",
            "deploy_app.sh": "Custom Deployment Script",
            "monitor.py": "System Monitoring Agent"
        }
        for script, description in allowlist.items():
            st.text(f"{script}: {description}")
        
        st.divider()
        
        st.subheader("Agent Status")
        st.success("✅ Monitor Agent: Ready")
        st.success("✅ Analyst Agent: Ready")
        st.success("✅ Commander Agent: Ready")

if __name__ == "__main__":
    main()
