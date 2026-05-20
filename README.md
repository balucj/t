# 🛡️ AI Cyber-Patch Sentinel — Agentic Swarm (Phase 2)

This project has evolved into a **Dual-Agent Autonomous Swarm** designed for privacy-safe vulnerability remediation on local and cloud-based (AWS) infrastructure.

## 🚀  Evolution: Targeted Remediation

The swarm now supports , which allows for surgical remediation based on external vulnerability reports (CSV).

### Core Architecture

1.  **Local Sentinel (The "Muscle"):** 
    *   Powered by `ollama/gemma4:e4b`.
    *   Handles SSH, IPs, credentials, and local file paths.
    *   Executes system-level tools via **MCP (Model Context Protocol)**.
2.  **Cloud Advisor (The "Brain"):**
    *   Powered by `openai/gpt-4o`.
    *   Receives **anonymized** technical data only.
    *   Recommends versions, generates manual install scripts (JSON), and performs Root Cause Analysis (RCA).

## 🗺️ Project Flow & Understanding

For a detailed look at how the system works, including a step-by-step diagram and a non-technical guide, please see:

👉 **[PROJECT_FLOW.md](./PROJECT_FLOW.md)**
👉 **[AI_DRIVEN_TESTING_FLOW.md](./AI_DRIVEN_TESTING_FLOW.md)**
👉 **[TECHNICAL_WORKFLOW.md](./TECHNICAL_WORKFLOW.md)**

---

## 🏗️ Phase 2 Workflow

The agent follows a strict, logically sequenced workflow for Phase 2:

1.  **CSV Ingestion**: Reads `vul_csv/sec-1123.csv` to identify target IP, package, and remediated version.
2.  **Login & OS Detection**: Connects via SSH and identifies the OS family and package manager.
3.  **Targeted Scan**: Verifies if the specific vulnerable package is present and if an update is available via the native manager (`winget`, `apt`, etc.).
4.  **Conditional Intelligence**:
    *   If updatable via manager: Queries Advisor for verification tests.
    *   If manual update required: Queries Advisor for download links and a JSON-formatted installation script.
5.  **AWS Snapshot**: Creates an EBS safety net before any changes.
6.  **Surgical Patching**: Deploys the patch using the native manager or the manual script.
7.  **Validation & Cleanup**: Runs 3 bash-based tests. Deletes snapshot on success; reverts on failure.

### Key Tools (MCP)
- `read_vulnerability_csv`: Ingests vulnerability reports.
- `detect_os`: Handles remote discovery.
- `run_vulnerability_scan`: Performs targeted package checks.
- `install_manual_package`: Executes custom installation commands.
- `create_aws_snapshot`: Manages cloud safety nets.

## 🛠️ Setup & Running

### Prerequisites
- **Ollama**: Local instance with `gemma4:e4b`.
- **OpenAI API Key**: Required for Cloud Intelligence.
- **AWS Credentials**: Required for EBS Snapshot support.

### Running the Swarm
```bash
python agent_coordinator.py
```

---

## 🌐 Nginx & Base Path Configuration

If you are hosting this application behind a reverse proxy (like Nginx) at a sub-path (e.g., `/sentinel/`), you must configure the `BASE_PATH`.

1.  **Set Environment Variable**: Add `BASE_PATH` to your `.env` or export it:
    ```bash
    export BASE_PATH=/sentinel
    ```

2.  **Nginx Configuration**: Use the following block to handle routing and Server-Sent Events (SSE):
    ```nginx
    location /sentinel/ {
        proxy_pass http://127.0.0.1:8000/; # Note the trailing slash
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /sentinel;

        # SSE Support (Crucial for live logs)
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_cache_off;
        proxy_buffering off;
        chunked_transfer_encoding on;
    }
    ```
