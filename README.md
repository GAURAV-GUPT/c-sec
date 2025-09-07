# 🛡️ Cybersecurity Threat Monitoring System

A real-time cybersecurity monitoring system that uses AI agents to detect, analyze, and respond to potential threats on your systems.

## 📋 Overview

This application simulates a cybersecurity monitoring system with three specialized AI agents:

1. **Monitor Agent**: Detects script executions on the system
2. **Analyst Agent**: Analyzes scripts against an allowlist and uses AI for threat assessment
3. **Commander Agent**: Takes action based on the analysis (allow or block)

## 🚀 Features

- **Real-time Monitoring**: Simulated detection of script executions
- **AI-Powered Analysis**: Uses OpenAI's GPT model to assess potential threats
- **Allowlist System**: Pre-approved scripts that are automatically trusted
- **Action Logging**: Complete audit trail of all security events
- **Interactive UI**: Streamlit-based web interface for easy interaction

## 🛠️ Installation

1. **Clone or download the project files**

2. **Install required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your OpenAI API key:**
   - Create a `.env` file in the project directory
   - Add your OpenAI API key:
     ```
     OPENAI_API_KEY=your_api_key_here
     ```
   - Get an API key from [OpenAI](https://platform.openai.com/)

## 🎯 How to Use

1. **Start the application:**
   ```bash
   streamlit run app.py
   ```

2. **Using the interface:**
   - **Simulate Scripts**: Use the buttons in the sidebar to simulate legitimate or malicious scripts
   - **Manual Analysis**: Enter a script path manually for analysis
   - **View Events**: See all security events in the main panel with detailed information
   - **Check Status**: View system status and allowlist contents in the right panel

3. **Understanding the workflow:**
   - When a script is detected, the Monitor Agent logs the event
   - The Analyst Agent checks against the allowlist and uses AI for additional analysis
   - The Commander Agent takes appropriate action based on the decision
   - All steps are logged and displayed in the interface

## 🔧 Configuration

### Allowlist Management
The system includes a predefined allowlist of trusted scripts. You can modify the `check_against_allowlist()` function to:
- Connect to a real database of approved scripts
- Implement hash-based verification
- Integrate with external threat intelligence services

### AI Analysis
The AI analysis can be customized by modifying the prompt in the `analyze_with_ai()` function to include:
- Specific threat indicators
- Company security policies
- Historical attack patterns

## 📊 Sample Use Cases

1. **Detecting Unknown Scripts**: The system will flag any script not in the allowlist
2. **AI Threat Assessment**: Suspicious scripts get additional AI analysis
3. **Incident Response**: Automated actions based on threat level
4. **Audit Trail**: Complete logging for compliance and investigation

## 🏗️ Architecture

```
User Interface (Streamlit)
       ↓
Script Detection Simulation
       ↓
    [Monitor Agent] → Logs detection
       ↓
    [Analyst Agent] → Checks allowlist → AI Analysis
       ↓
   [Commander Agent] → Takes action (Allow/Block)
       ↓
        SIEM Logging → Event Storage
```

## 🔒 Security Considerations

- This is a simulation tool for demonstration purposes
- In production, implement proper authentication and authorization
- Secure your OpenAI API key and other credentials
- Consider adding rate limiting for API calls
- Implement proper error handling and logging

## 🚨 Limitations

- Currently simulates file system monitoring rather than real monitoring
- Does not actually terminate processes or quarantine files (simulation only)
- Requires an internet connection for AI analysis
- Dependent on OpenAI API availability

## 📈 Future Enhancements

- Real file system monitoring integration
- Integration with actual EDR/SIEM systems
- Multi-factor authentication for critical actions
- Historical analysis and trend reporting
- Customizable alert thresholds
- Team collaboration features

## 🤝 Contributing

Feel free to fork this project and submit pull requests for:
- Additional monitoring capabilities
- Enhanced AI analysis prompts
- UI improvements
- Integration with other security tools

## 📄 License

This project is for educational and demonstration purposes. Please ensure proper licensing for any components used in production environments.

---

**Note**: This tool is designed for educational purposes and should be thoroughly tested before use in production environments. Always follow your organization's security policies and procedures.
