# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🚀 Project Overview

AI Cyber-Patch Sentinel — Agentic Swarm (Phase 2) is a dual-agent autonomous system for privacy-safe vulnerability remediation. It consists of:
- **Local Sentinel**: Handles SSH, system operations via MCP tools (powered by ollama/gemma4:e4b)
- **Cloud Advisor**: Receives anonymized data, recommends fixes, generates scripts (powered by openai/gpt-4o)

## ⚙️ Development Commands

### Setup
```bash
# Create virtual environment (if not exists)
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env  # Edit with your settings
```

### Running the System
```bash
# Start the agent coordinator (main entrypoint)
python agent_coordinator.py

# Access dashboard at http://127.0.0.1:8000
```

### Testing
```bash
# Run specific tests
python test_advisor.py
python test_core_flow.py
python test_aws.py
```

### Logs & Monitoring
- Primary log: `agent_coordinator.log` (rotating, 5MB)
- MCP server log: `sentinel_mcp.log`
- Streamlit/UI logs: Check terminal output

## 🏗️ Architecture Summary

### Core Components
1. **agent_coordinator.py** - Main orchestrator implementing ReAct loop:
   - CSV ingestion → OS detection → Targeted scan → Conditional intelligence
   - AWS snapshotting → Surgical patching → Validation/cleanup

2. **mcp_sentinel_server.py** - MCP backbone exposing tools:
   - `detect_os` - Remote OS/package manager detection
   - `run_vulnerability_scan` - Targeted package checks
   - `create_aws_snapshot` - EBS safety nets
   - `deploy_patch`/`install_manual_package` - Patch execution
   - `read_vulnerability_csv` - Ingest remediation reports

3. **advisor.py** - Cloud Advisor component:
   - Receives anonymized technical data
   - Uses GPT-4o for version recommendations & RCA
   - Generates JSON installation scripts

4. **swarm_ui.py** - Streamlit dashboard for monitoring/control

### Data Flow (Phase 2 Workflow)
1. **CSV Ingestion**: Reads `vul_csv/*.csv` for target IP, package, fixed version
2. **OS Detection**: SSH connection to identify distro/package manager (apt, etc.)
3. **Targeted Scan**: Verify package presence & update availability via native manager
4. **Conditional Intelligence**:
   - If updatable via manager: Advisor suggests verification tests
   - If manual update: Advisor provides download links + JSON install script
5. **AWS Snapshot**: Creates EBS pre-change safety net
6. **Surgical Patching**: Deploys via native package manager or custom script
7. **Validation**: Runs 3 bash tests; deletes snapshot on success, reverts on failure

### Key Files Reference
- `.env` - Configuration (SSH creds, API keys, AWS settings, targets)
- `vul_csv/` - Directory for vulnerability CSV reports (format: IP, package, fixed_version)
- `requirements.txt` - Dependencies (MCP, LiteLLM, Paramiko, boto3, etc.)

## 🔑 Important Notes

- **Credentials**: Store SSH/AWS keys securely; `.env` is for development only
- **Demo Mode**: System can run with simulated output for testing
- **MCP Communication**: All agent-server communication via stdio MCP transport
- **Privacy Design**: Advisor receives only anonymized technical data (no IPs, credentials)
- **Safety**: Snapshots required before any changes; automatic rollback on validation failure

## 📊 Current Focus (from codebase)
- Enhancing error log analysis in testing phase
- Multi-target config for separate Sandbox/Prod SSH credentials
- Final end-to-end testing on live Debian/Ubuntu targets