"""
╔══════════════════════════════════════════════════════════════════╗
║  Agent Coordinator — The Swarm Brain                           ║
║  Phase 1: Agentic AI Evolution for AI Cyber-Patch Sentinel     ║
║                                                                ║
║  Connects to mcp_sentinel_server.py via MCP stdio transport,   ║
║  uses LiteLLM (ollama/gemma4:e4b) for reasoning, and drives   ║
║  a ReAct loop: Detect OS → Scan → Snapshot → Patch.           ║
╚══════════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import sys
import os
import traceback
from typing import Any

from dotenv import load_dotenv
import litellm
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from loguru import logger

from swarm_ui import SentinelDashboard, swarm_state

# ── Configuration ──────────────────────────────────────────────
load_dotenv()  # Load variables from .env
litellm.drop_params = True

LLM_MODEL = os.getenv("LLM_MODEL", "ollama/gemma4:e4b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# ── VRAM / Resource Limits ──────────────────────────────────────
# Tuned for 6 GB VRAM (RTX 4050 Laptop) running a 9.6 GB model.
# num_ctx  — Context window tokens. Lower = less KV-cache VRAM.
#            Default Ollama uses 8192+; we cap at 4096 to stay safe.
# num_gpu  — Number of model layers offloaded to GPU. Set to -1
#            for full GPU or a lower int (e.g. 24) to split GPU/CPU.
#            Set 0 for full CPU (slow but zero VRAM usage).
# max_tokens — Max response tokens. Reduced from 4096 to 2048.
# MAX_HISTORY_MESSAGES — Max messages kept in conversation. Older
#            tool results are summarised to free context.
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "4096"))
OLLAMA_NUM_GPU = int(os.getenv("OLLAMA_NUM_GPU", "-1"))    # -1 = auto
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "2048"))
MAX_HISTORY_MESSAGES = int(os.getenv("MAX_HISTORY_MESSAGES", "20"))
MAX_INSTALL_RETRIES = int(os.getenv("MAX_INSTALL_RETRIES", "3"))
MAX_TEST_RETRIES = int(os.getenv("MAX_TEST_RETRIES", "3"))

# Target defaults (loaded from .env)
TARGET_HOST = os.getenv("TARGET_HOST", "127.0.0.1")
TARGET_USER = os.getenv("TARGET_USER", "root")
TARGET_PORT = int(os.getenv("TARGET_PORT", "22"))
TARGET_KEY_PATH = os.getenv("TARGET_KEY_PATH", "")
TARGET_PASSWORD = os.getenv("TARGET_PASSWORD", "master")

# Cloud Provider Configuration
CLOUD_PROVIDER = os.getenv("CLOUD_PROVIDER", "AWS").upper()

# AWS Configuration
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "eu-north-1")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")

# GCP Configuration
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID", "")
GCP_ZONE = os.getenv("GCP_ZONE", "us-central1-a")
GCP_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")

from advisor import CloudAdvisor

advisor = CloudAdvisor(OPENAI_API_KEY)

# Path to the MCP server script
MCP_SERVER_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "mcp_sentinel_server.py",
)

MAX_REACT_ITERATIONS = 20

# ── Logger ──────────────────────────────────────────────────────
logger.remove()
logger.add(
    "agent_coordinator.log",
    rotation="5 MB",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {file}:{function}:{line} - {message}",
    level="DEBUG",
)
# logger.add(sys.stderr, level="WARNING")
dashboard = None

# ── System Prompt ──────────────────────────────────────────────

SYSTEM_PROMPT = """You are the Sentinel Orchestrator. You fix vulnerabilities on target servers.

## PRIVACY
NEVER share IPs, user names, or passwords with the 'consult_advisor' tool.

## YOUR TOOLS (Call one at a time using JSON: {"tool": "...", "input": {...}})
1. **run_vulnerability_scan**: Check if a package is installed. (args: host, user, password, package, pkg_manager)
2. **consult_advisor**: Ask GPT-4o for technical help. (args: prompt)
3. **create_aws_snapshot**: Backup before patching (AWS targets). (args: host)
4. **create_gcp_snapshot**: Backup before patching (GCP targets). (args: host, project_id, zone, credentials_path)
5. **deploy_patch**: Update a package. (args: host, user, password, package, version, pkg_manager, install_commands: list, verify_command: string)
6. **install_manual_package**: Run custom update commands. (args: host, user, password, install_commands, package)
7. **run_custom_test**: Verify the fix. (args: host, user, password, test_command)
8. **delete_aws_snapshot**: Cleanup after ALL patches are done (AWS). (args: snapshot_ids)
9. **delete_gcp_snapshot**: Cleanup after ALL patches are done (GCP). (args: snapshot_names, project_id, credentials_path)

## WORKFLOW (CRITICAL)
For EACH vulnerability in the user's list:
1. SCAN: run_vulnerability_scan (confirm package is present using the detected pkg_manager)
2. SNAPSHOT: Use the appropriate tool based on the cloud provider (AWS: create_aws_snapshot, GCP: create_gcp_snapshot) once only - MUST do before advice.
3. INTELLIGENCE: consult_advisor (Ask for: 1. Severity 0-100, 2. Warnings, 3. Procedure: command list)
4. PATCH: deploy_patch OR install_manual_package (using the command list from step 3)
5. VERIFY: run_custom_test (using the validation command from step 3)
6. CLEANUP: Cleanup snapshots only at the end using delete_aws_snapshot or delete_gcp_snapshot.

Do NOT repeat a step if it succeeded. Move to the next step immediately.
Format: Provide a JSON tool call ONLY. No conversational text."""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool Caller
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def call_mcp_tool(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    """Call an MCP tool and return the result as a string."""
    
    # ── Tool Alias Mapping (Fix Hallucinations) ──────────────────
    alias_map = {
        "get_os_info": "detect_os",
        "get_system_info": "detect_os",
        "scan_package": "run_vulnerability_scan",
        "check_installation": "run_vulnerability_scan",
        "create_snapshot": "create_aws_snapshot" if CLOUD_PROVIDER == "AWS" else "create_gcp_snapshot",
        "execute_winget": "deploy_patch",
        "execute_winget_upgrade": "deploy_patch",
        "execute_winget_command": "deploy_patch",
        "execute_apt_upgrade": "deploy_patch",
    }
    if tool_name in alias_map:
        swarm_state.add_log(f"⚠️ Aliasing hallucinated tool '{tool_name}' → '{alias_map[tool_name]}'", level="WARN", agent="System")
        logger.info(f"Aliasing hallucinated tool '{tool_name}' → '{alias_map[tool_name]}'")
        tool_name = alias_map[tool_name]

    swarm_state.add_log(
        f"→ {tool_name}({', '.join(f'{k}={v!r}' for k, v in arguments.items())})",
        level="ACTION",
        agent="MCP",
    )
    logger.info(f"Calling MCP tool '{tool_name}' with arguments'")

    try:
        result = await session.call_tool(tool_name, arguments=arguments)
        logger.info(result)

        # Extract text content from MCP result
        if hasattr(result, "content") and result.content:
            text_parts = []
            for block in result.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)
            output = "\n".join(text_parts) if text_parts else str(result)
        else:
            output = str(result)

        # Log truncated result to UI
        preview = output[:200] + "…" if len(output) > 200 else output
        swarm_state.add_log(f"← {tool_name}: {preview}", level="RESULT", agent="MCP")
        logger.info(f"← {tool_name}: {output}")
        return output

    except Exception as e:
        error_msg = f"Tool call failed: {tool_name} — {e}"
        swarm_state.add_log(error_msg, level="ERROR", agent="MCP")
        logger.error(f"Tool call failed: {tool_name} — {e}")
        logger.error(f"{error_msg}\n{traceback.format_exc()}")
        return json.dumps({"error": str(e)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LLM Interaction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_tools_schema(tools_list: list) -> list[dict]:
    """Convert MCP tool definitions to OpenAI-style function schemas for LiteLLM."""
    schemas = []
    for tool in tools_list:
        # Build parameter properties from MCP tool input schema
        properties = {}
        required = []

        if hasattr(tool, "inputSchema") and tool.inputSchema:
            schema = tool.inputSchema
            properties = schema.get("properties", {})
            required = schema.get("required", [])

        schemas.append({
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        })
    return schemas


async def llm_completion(
    messages: list[dict],
    tools: list[dict],
) -> dict:
    """Call the LLM via LiteLLM with tool-calling support.
    
    Passes num_ctx and num_gpu to Ollama to cap VRAM usage.
    """
    # Build Ollama-specific options to limit VRAM
    extra_kwargs = {}
    if "ollama" in LLM_MODEL:
        extra_kwargs["num_ctx"] = OLLAMA_NUM_CTX
        if OLLAMA_NUM_GPU >= 0:
            extra_kwargs["num_gpu"] = OLLAMA_NUM_GPU

    try:
        completion_kwargs = {
            "model": LLM_MODEL,
            "messages": messages,
            "api_base": OLLAMA_BASE_URL,
            "temperature": 0.0,
            "max_tokens": LLM_MAX_TOKENS,
            **extra_kwargs,
        }
        if tools:
            completion_kwargs["tools"] = tools
            completion_kwargs["tool_choice"] = "auto"

        response = await asyncio.to_thread(
            litellm.completion,
            **completion_kwargs,
        )
        return response
    except Exception as e:
        logger.error(f"LLM completion failed: {e}")
        swarm_state.add_log(f"LLM error: {e}", level="ERROR", agent="LLM")

        raise


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Deterministic Pipeline
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _parse_advisor_response(data) -> tuple[list[str], str]:
    logger.info(f"Advisor data: {data} (Type: {type(data)})")
    logger.info("*-*"*50)
    """Surgically extract PROCEDURE and VALIDATION commands from Advisor response."""
    import re
    install_commands = []
    verify_command = ""

    # If data is a string, it might be an error or a JSON string
    if isinstance(data, str):
        try:
            import json
            data = json.loads(data)
        except:
            # Not JSON, maybe it's an error message
            logger.error(f"Cannot parse advisor response as JSON: {data}")
            return [], ""

    if not isinstance(data, dict):
        logger.error(f"Advisor response is not a dictionary: {data}")
        return [], ""

    # Set restart requirement in state
    swarm_state.restart_required = data.get("RESTART_REQUIRED", False)
    if swarm_state.restart_required:
        swarm_state.add_log("Cloud Advisor indicates a restart is required for this patch.", level="WARN", agent="CloudAdvisor")

    # Strategy: Look for the PROCEDURE section
    if data.get("PROCEDURE"):
        proc_data = data.get("PROCEDURE")
        raw_cmds = proc_data if isinstance(proc_data, list) else proc_data.splitlines()
        
        install_commands = []
        for line in raw_cmds:
            line = line.strip().strip("*-# `")
            if not line: continue
            
            # Reject placeholders like <conflicting_service> or [package]
            if re.search(r'[<\[][A-Z0-9_]+[>\]]', line, re.I):
                logger.warning(f"Rejecting command with placeholder: {line}")
                continue

            # Fail-safe for non-interactive apt
            if any(line.lower().startswith(kw) for kw in ("apt ", "apt-get")):
                if "-y" not in line.lower():
                    line = line.replace("apt ", "apt-get -y ").replace("install", "install -y").replace("-y -y", "-y")
                    if "DEBIAN_FRONTEND" not in line:
                        line = f"DEBIAN_FRONTEND=noninteractive {line}"
            
            install_commands.append(line)
        
    if data.get("VALIDATION"):
        val_data = data.get("VALIDATION")
        verify_command = ""
        if isinstance(val_data, list):
            verify_command = " && ".join(val_data)
        elif isinstance(val_data, str):
            v_match = re.search(r'`([^`]+)`', val_data)
            if v_match:
                verify_command = v_match.group(1)
            else:
                for line in val_data.splitlines():
                    if line.strip():
                        verify_command = line.strip().strip("*-# ")
                        break
        
        # Reject placeholders in validation too
        if re.search(r'[<\[][A-Z0-9_]+[>\]]', verify_command, re.I):
            logger.warning(f"Rejecting validation with placeholder: {verify_command}")
            verify_command = ""
            
    return install_commands, verify_command

async def run_pipeline(session: ClientSession, target_index: int = None):
    """
    Programmatic Workflow:
    Ingest CSV → Detect OS → For each Vuln (or specific index): Scan → Advisor → Snapshot → Patch → Verify
    """
    swarm_state.add_log(f"🚀 Starting Pipeline ({'Single' if target_index is not None else 'Autonomous'} Mode)...", level="INFO", agent="System")
    swarm_state.set_phase("DETECTING")
    
    # 1. DISCOVERY (Deterministic pre-execution)
    discovery = await _pre_execute_discovery(session)
    if not discovery.get("vulnerabilities"):
        swarm_state.add_log("No vulnerabilities to process. Mission Aborted.", level="WARN", agent="System")
        return "No vulnerabilities found."

    target_ip = discovery["target_ip"]
    os_info = discovery.get("os_info")
    
    if not os_info or "error" in os_info:
        err = os_info.get("error", "Unknown OS detection error") if os_info else "Discovery failed"
        swarm_state.add_log(f"Mission Aborted: {err}", level="ERROR", agent="System")
        swarm_state.set_phase("ERROR")
        return f"Aborted: {err}"

    pkg_mgr = os_info.get("pkg_manager", "unknown")

    # 2. FILTER VULNERABILITIES IF TARGETED
    vulns_to_process = discovery["vulnerabilities"]
    if target_index is not None:
        if 0 <= target_index < len(vulns_to_process):
            vulns_to_process = [vulns_to_process[target_index]]
            swarm_state.add_log(f"Targeted fix for: {vulns_to_process[0].get('package')}", level="INFO", agent="System")
        else:
            swarm_state.add_log(f"Invalid target index: {target_index}", level="ERROR", agent="System")
            return "Invalid index"

    # 3. PROCESS VULNERABILITIES
    snapshot_created = False
    results = []

    for idx, vuln in enumerate(vulns_to_process):
        package = vuln.get("package", "Unknown")
        version = vuln.get("remediation_version", "latest")

        swarm_state.add_log(f"Processing ({idx+1}/{len(vulns_to_process)}): {package}", level="INFO", agent="Pipeline")
        swarm_state.set_phase("SCANNING")

        # Step A: Targeted Scan & Usage Audit
        scan_args = _inject_defaults({
            "host": target_ip, "package": package, "pkg_manager": pkg_mgr, "remediation_version": version
        })
        scan_res_raw = await call_mcp_tool(session, "run_vulnerability_scan", scan_args)
        _update_dashboard_from_tool("run_vulnerability_scan", scan_args, scan_res_raw)

        try:
            scan_data = json.loads(scan_res_raw)
        except (json.JSONDecodeError, TypeError):
            swarm_state.add_log(f"Error parsing scan result for {package}.", level="ERROR", agent="Pipeline")
            results.append(f"{package}: Scan Result Parse Error")
            continue

        if scan_data.get("status") == "NOT_INSTALLED":
            swarm_state.add_log(f"Skipping {package}: Not found on target.", level="WARN", agent="Pipeline")
            results.append(f"{package}: Not Installed")
            continue
        else:
            package = scan_data.get("id", package)

        # NEW: Application Usage Audit
        swarm_state.add_log(f"Auditing service state for {package} before patching...", level="THINK", agent="Pipeline")
        usage_args = _inject_defaults({"host": target_ip, "package": package})
        usage_res_raw = await call_mcp_tool(session, "check_package_usage", usage_args)
        try:
            usage_data = json.loads(usage_res_raw)
            running_procs = usage_data.get("running_processes", [])
            active_services = usage_data.get("systemd_services", [])
            swarm_state.add_log(f"Pre-patch audit: Found {len(running_procs)} processes and {len(active_services)} services for {package}.", level="RESULT", agent="Pipeline")
        except:
            swarm_state.add_log(f"Usage audit failed for {package}, proceeding with caution.", level="WARN", agent="Pipeline")
            usage_data = {}

        # Step B: Get Intelligence (ChatGPT)
        swarm_state.add_log(f"Consulting Cloud Advisor for {package} update strategy...", level="THINK", agent="Pipeline")
        prompt = (
            f"How to update {package} to {version} using {pkg_mgr} on {os_info.get('os_family')}?\n"
            f"PRE-PATCH AUDIT: {json.dumps(usage_data)}\n"
            "CRITICAL CONSTRAINTS:\n"
            "1. If services are running, include commands to RESTART or RELOAD them after patching.\n"
            "2. Provide a validation test that confirms the service is running and ports are open.\n"
            "3. ALL package manager commands MUST be non-interactive. For 'apt', use: 'DEBIAN_FRONTEND=noninteractive apt-get install -y ...'."
        )
        advisor_text = advisor.get_intelligence(prompt)
        logger.success(advisor_text)

        install_cmds, verify_cmd = _parse_advisor_response(advisor_text)
        swarm_state.add_log(f"Advisor suggested {len(install_cmds)} command(s) for {package}.", level="RESULT", agent="CloudAdvisor")

        # Step C: Snapshot (Once per session)
        if not snapshot_created:
            swarm_state.set_phase("SNAPSHOTTING")
            snap_args = _inject_defaults({"host": target_ip})
            snap_tool = "create_aws_snapshot" if CLOUD_PROVIDER == "AWS" else "create_gcp_snapshot"
            snap_res_raw = await call_mcp_tool(session, snap_tool, snap_args)
            _update_dashboard_from_tool(snap_tool, snap_args, snap_res_raw)
            snapshot_created = True

        # Step D: Patch & Verify with Retries
        attempts = 0
        patch_success = False
        all_failure_logs = []
        patch_data = {}

        while attempts <= MAX_INSTALL_RETRIES and not patch_success:
            if attempts > 0:
                swarm_state.add_log(f"🔄 Retry Attempt {attempts}/{MAX_INSTALL_RETRIES} for {package}...", level="WARN", agent="Pipeline")
                # Consult Advisor for Retry Strategy
                retry_prompt = (
                    f"The previous installation attempt for {package} to version {version} failed. "
                    f"Previous failures logs: {all_failure_logs[-1] if all_failure_logs else 'No logs'}. "
                    f"Suggest a different retry strategy (different commands or fixes). "
                    f"Format output as JSON with PROCEDURE and VALIDATION."
                )
                advisor_text = advisor.get_intelligence(retry_prompt)
                install_cmds, verify_cmd = _parse_advisor_response(advisor_text)

            swarm_state.set_phase("PATCHING")
            patch_args = _inject_defaults({
                "host": target_ip,
                "package": package,
                "pkg_manager": pkg_mgr,
                "install_commands": install_cmds,
                "verify_command": verify_cmd
            })
            patch_res_raw = await call_mcp_tool(session, "deploy_patch", patch_args)
            _update_dashboard_from_tool("deploy_patch", patch_args, patch_res_raw)

            try:
                patch_data = json.loads(patch_res_raw)
                
                # ── Step AI-STATUS: Use Local LLM to confirm if update actually happened or if it failed incorrectly ──
                swarm_state.add_log("Asking local AI to evaluate patch results...", level="THINK", agent="Pipeline")
                try:
                    eval_prompt = (
                        f"Evaluate the package installation output for '{package}' (target version: {version}).\n"
                        f"Output: {json.dumps(patch_data.get('install_output', []))}\n"
                        "Status returned by tool: " + patch_data.get("status", "unknown") + "\n\n"
                        "Respond with ONLY one word:\n"
                        "1. 'UPDATED' - if it was successfully upgraded.\n"
                        "2. 'SKIPPED' - if it was already at the newest version.\n"
                        "3. 'FAILED' - if there was a real error (like 'Version not found' or network error)."
                    )
                    eval_resp = await llm_completion([{"role": "user", "content": eval_prompt}], None)
                    eval_text = eval_resp.choices[0].message.content.strip().upper()
                    
                    if "SKIPPED" in eval_text:
                        swarm_state.add_log(f"Local AI determined {package} is already at newest version. Marking as SKIPPED.", level="WARN", agent="Pipeline")
                        patch_success = True
                        patch_data["ai_status"] = "SKIPPED"
                        patch_data["status"] = "success" # Override to success if it was already up-to-date
                    elif "UPDATED" in eval_text and patch_data.get("status") == "success":
                        patch_data["ai_status"] = "UPDATED"
                    else:
                        patch_data["ai_status"] = "FAILED"
                except Exception as eval_err:
                    swarm_state.add_log(f"⚠️ Local AI evaluation unavailable: {eval_err}. Falling back to tool status.", level="WARN", agent="Pipeline")
                    logger.warning(f"Local AI evaluation failed: {eval_err}")
                    patch_data["ai_status"] = "UPDATED" if patch_data.get("status") == "success" else "FAILED"

                if patch_data.get("status") == "success":
                    # Step E: Verify with Test Retries
                    swarm_state.set_phase("PATCHED")
                    if not verify_cmd:
                        patch_success = True # No verification required, assume success
                    else:
                        test_attempts = 0
                        test_passed = False
                        current_verify_cmd = verify_cmd
                        test_failures = []

                        while test_attempts <= MAX_TEST_RETRIES and not test_passed:
                            if test_attempts > 0:
                                swarm_state.add_log(f"🔄 Test Retry {test_attempts}/{MAX_TEST_RETRIES} for {package}...", level="WARN", agent="Pipeline")
                                # Consult Advisor for Test Retry Strategy
                                test_retry_prompt = (
                                    f"The patch for {package} to version {version} was technically successful, but the validation test failed. "
                                    f"Test Command: {current_verify_cmd}. "
                                    f"Failure logs: {test_failures[-1] if test_failures else 'No logs'}. "
                                    f"Should I try a different validation command or is there a common post-install fix (like a service restart)? "
                                    f"Format output as JSON with PROCEDURE (for fixes) and VALIDATION (for the test)."
                                )
                                advisor_text = advisor.get_intelligence(test_retry_prompt)
                                fix_cmds, new_verify_cmd = _parse_advisor_response(advisor_text)
                                
                                # Run any suggested fixes before re-testing
                                for fix_cmd in fix_cmds:
                                    swarm_state.add_log(f"Applying post-test fix: {fix_cmd}", level="ACTION", agent="Pipeline")
                                    await call_mcp_tool(session, "run_custom_test", _inject_defaults({"host": target_ip, "test_command": fix_cmd}))
                                
                                current_verify_cmd = new_verify_cmd or current_verify_cmd

                            test_args = _inject_defaults({
                                "host": target_ip, "test_command": current_verify_cmd, "description": f"Post-patch validation: {package}"
                            })
                            test_res_raw = await call_mcp_tool(session, "run_custom_test", test_args)
                            test_data = json.loads(test_res_raw)
                            
                            if test_data.get("status") == "passed":
                                test_passed = True
                                patch_success = True
                            else:
                                test_failures.append(f"Attempt {test_attempts}: {test_res_raw}")
                                test_attempts += 1
                        
                        if not test_passed:
                            all_failure_logs.append(f"Testing failed after {MAX_TEST_RETRIES} attempts: {test_failures}")
                            # Internal RCA for test failure
                            test_rca_prompt = (
                                f"Verification failed for {package} after {MAX_TEST_RETRIES} retries. "
                                f"The patch was applied, but tests consistently failed. "
                                f"Test failures: {test_failures}. "
                                f"Provide an RCA for the verification failure."
                            )
                            test_rca = advisor.get_intelligence(test_rca_prompt)
                            swarm_state.add_log(f"📝 Test RCA: {str(test_rca)[:200]}...", level="ERROR", agent="CloudAdvisor")
                            logger.error(f"Test RCA for {package}: {test_rca}")

                else:
                    all_failure_logs.append(f"Patch failed: {patch_res_raw}")
            except (json.JSONDecodeError, TypeError) as e:
                all_failure_logs.append(f"JSON Parse error: {str(e)}")

            if not patch_success:
                attempts += 1

        if patch_success:
            ai_stat = patch_data.get("ai_status", "UPDATED")
            msg = f"{package}: {ai_stat} and Verified Successfully (Attempts: {attempts if attempts > 0 else 1})"
            if ai_stat == "SKIPPED":
                msg = f"{package}: Already at newest version (Verified by Local AI)"
            
            # Final Safety Check: Verify status is still passed
            if not patch_success: # This is a logical flag we can set
                results.append(f"{package}: Verification Failed despite version match.")
            else:
                results.append(msg)
        else:
            swarm_state.set_phase("ERROR")
            # ... rest of the code
            # Step F: RCA on failure
            swarm_state.add_log(f"❌ All {MAX_INSTALL_RETRIES} retries failed for {package}. Generating RCA...", level="ERROR", agent="Pipeline")
            rca_prompt = (
                f"Root Cause Analysis request for failed installation of {package}. "
                f"We tried {MAX_INSTALL_RETRIES} times and failed. "
                f"Failure history: {all_failure_logs}. "
                f"Explain why it likely failed and suggest manual steps."
            )
            rca_text = advisor.get_intelligence(rca_prompt)
            swarm_state.add_log(f"📝 RCA for {package}: {str(rca_text)[:200]}...", level="RESULT", agent="CloudAdvisor")
            logger.error(f"RCA for {package}: {rca_text}")
            results.append(f"{package}: Patch Failed after {MAX_INSTALL_RETRIES} retries. RCA generated.")
            
    summary = "\n".join(results)
    if any("Failed" in res for res in results) or any("Error" in res for res in results):
        swarm_state.set_phase("ERROR")
        swarm_state.add_log(f"Pipeline finished with ERRORS. Summary:\n{summary}", level="ERROR", agent="System")
    else:
        swarm_state.set_phase("VERIFIED")
        swarm_state.add_log(f"Pipeline finished successfully. Summary:\n{summary}", level="RESULT", agent="System")
    
    return f"Pipeline Finished.\n{summary}"

def _inject_defaults(args: dict) -> dict:
    """Inject default SSH connection params and AWS/GCP region/credentials if not provided."""
    defaults = {
        "host": TARGET_HOST,
        "user": TARGET_USER,
        "port": TARGET_PORT,
        "key_path": TARGET_KEY_PATH,
        "password": TARGET_PASSWORD,
        "region": AWS_REGION,
        "aws_access_key": AWS_ACCESS_KEY,
        "aws_secret_key": AWS_SECRET_KEY,
        "project_id": GCP_PROJECT_ID,
        "zone": GCP_ZONE,
        "credentials_path": GCP_CREDENTIALS,
    }
    for key, default in defaults.items():
        if key not in args or not args[key]:
            args[key] = default
    return args


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Text-Based Tool Call Extraction (LLM Compatibility Layer)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _extract_tool_calls_from_text(text: str) -> list[dict] | None:
    """
    Extract tool calls from LLM text output when the model doesn't use
    native tool_calls format (common with gemma4, llama, etc.).

    Handles patterns:
      - {"tool_calls": [{"function": {"name": "...", "arguments": {...}}}]}
      - {"action": {"name": "...", "arguments": {...}}}
      - {"tool": "...", "input": {...}}
      - {"tool_name": "...", "params": {...}}
      - {"tool_name": "...", "tool_input": {...}}
    """
    try:
        start = text.find('{')
        end = text.rfind('}')
        if start == -1 or end == -1:
            return None

        json_str = text[start:end + 1]
        data = json.loads(json_str)

        tool_calls = []

        # Pattern 1: {"tool_calls": [...]}
        if "tool_calls" in data and isinstance(data["tool_calls"], list):
            for tc in data["tool_calls"]:
                if isinstance(tc, dict):
                    if "function" in tc and isinstance(tc["function"], dict):
                        tool_calls.append({
                            "name": tc["function"].get("name", ""),
                            "arguments": tc["function"].get("arguments", {}),
                        })
                    elif "function" in tc and isinstance(tc["function"], str):
                        tool_calls.append({
                            "name": tc["function"],
                            "arguments": tc.get("args", tc.get("arguments", {})),
                        })

        # Pattern 2: {"action": {"name": "...", "arguments": {...}}}
        elif "action" in data and isinstance(data["action"], dict):
            action = data["action"]
            if "name" in action:
                tool_calls.append({
                    "name": action["name"],
                    "arguments": action.get("arguments", {}),
                })

        # Pattern 3: {"tool": "...", "input"/"arguments": {...}}
        elif "tool" in data and isinstance(data["tool"], str):
            tool_calls.append({
                "name": data["tool"],
                "arguments": data.get("input", data.get("arguments", {})),
            })

        # Pattern 4: {"tool_name": "...", "params"/"tool_input": {...}}
        elif "tool_name" in data and isinstance(data["tool_name"], str):
            tool_calls.append({
                "name": data["tool_name"],
                "arguments": data.get("params", data.get("tool_input", {})),
            })

        # Filter to only VALID tool names (reject hallucinated tools like 'print', 'tool_code')
        _VALID_TOOLS = {
            "detect_os", "scan_target", "run_vulnerability_scan", "create_snapshot",
            "deploy_patch", "install_manual_package", "check_package_usage",
            "run_custom_test", "read_vulnerability_csv", "create_aws_snapshot",
            "delete_aws_snapshot", "rollback_aws_snapshot", "consult_advisor",
            "create_gcp_snapshot", "delete_gcp_snapshot",
            "get_os_info", "get_system_info", "scan_package", "check_installation",
            "execute_winget", "execute_winget_upgrade", "execute_winget_command",
            "execute_apt_upgrade",
        }
        tool_calls = [tc for tc in tool_calls if tc.get("name") in _VALID_TOOLS]
        return tool_calls if tool_calls else None

    except (json.JSONDecodeError, KeyError, TypeError):
        return None


# Known tool names (real + commonly hallucinated) for intent detection
_KNOWN_TOOLS = {
    "detect_os", "scan_target", "run_vulnerability_scan", "create_snapshot",
    "deploy_patch", "install_manual_package", "check_package_usage",
    "run_custom_test", "read_vulnerability_csv", "create_aws_snapshot",
    "delete_aws_snapshot", "rollback_aws_snapshot", "consult_advisor",
    "create_gcp_snapshot", "delete_gcp_snapshot",
    # Common hallucinated names
    "get_os_info", "get_system_info", "scan_package", "check_installation",
    "execute_winget", "execute_winget_upgrade", "execute_winget_command",
    "execute_apt_upgrade",
}


def _looks_like_tool_intent(text: str) -> bool:
    """Check if text contains patterns suggesting the LLM intended to call a tool."""
    text_lower = text.lower()
    tool_mentions = sum(1 for t in _KNOWN_TOOLS if t in text_lower)
    json_patterns = sum(
        1 for p in ['"tool_calls"', '"tool_name"', '"tool":', '"action":', '"function":']
        if p in text_lower
    )
    return tool_mentions >= 1 and json_patterns >= 1


def _update_dashboard_from_tool(tool_name: str, args: dict, result: str):
    """Update the swarm dashboard state based on tool execution results."""
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return

    if tool_name == "detect_os":
        swarm_state.set_phase("DETECTING")
        os_family = data.get("os_family", "Unknown")
        pkg_mgr = data.get("pkg_manager", "unknown")
        host = args.get("host", TARGET_HOST)
        port = args.get("port", TARGET_PORT)
        has_error = "error" in data
        swarm_state.set_target(
            host, port, os_family, pkg_mgr, connected=not has_error
        )
        if not has_error:
            swarm_state.add_log(
                f"Detected: {os_family} — {pkg_mgr} on {data.get('hostname', host)}",
                level="RESULT", agent="Discovery",
            )
            logger.info(f"Detected: {os_family} — {pkg_mgr} on {data.get('hostname', host)}")

    elif tool_name == "read_vulnerability_csv":
        vulns = data.get("vulnerabilities", [])
        swarm_state.add_log(
            f"CSV Ingested: {len(vulns)} vulnerability records found",
            level="RESULT", agent="Ingestor",
        )
        logger.info(f"CSV Ingested: {len(vulns)} vulnerability records found")

    elif tool_name == "scan_target" or tool_name == "run_vulnerability_scan":
        status = data.get("status", "unknown")
        pkg = data.get("package", "unknown")
        if status == "INSTALLED_UPDATABLE":
            swarm_state.add_log(f"Package {pkg} is present and updatable via manager.", level="RESULT", agent="Scanner")
            logger.info(f"Package {pkg} is present and updatable via manager.")
        elif status == "INSTALLED_MANUAL_REQUIRED":
            swarm_state.add_log(f"Package {pkg} is present but requires manual update.", level="WARN", agent="Scanner")
            logger.warning(f"Package {pkg} is present but requires manual update.")
        elif status == "NOT_INSTALLED":
            swarm_state.add_log(f"Package {pkg} not found on server. Skipping.", level="INFO", agent="Scanner")
            logger.info(f"Package {pkg} not found on server. Skipping.")
        else:
            # Traditional scan_target
            total = data.get("total_upgradable", 0)
            swarm_state.add_log(
                f"Scan complete: {total} upgradable package(s) found",
                level="RESULT", agent="Scanner",
            )
            logger.info(f"Scan complete: {total} upgradable package(s) found")
            if total > 0:
                swarm_state.set_phase("SCANNED")

    elif tool_name == "create_snapshot":
        swarm_state.set_phase("SNAPSHOTTING")
        status = data.get("status", "unknown")
        path = data.get("snapshot_path", "")
        if status == "success":
            swarm_state.set_phase("SNAPSHOT_READY")
            swarm_state.set_snapshot(path)
            swarm_state.add_log(
                f"Snapshot ready: {path}", level="RESULT", agent="Snapshot"
            )
            logger.info(f"Snapshot ready: {path}")

    elif tool_name == "create_aws_snapshot":
        swarm_state.set_phase("SNAPSHOTTING")
        status = data.get("status", "unknown")
        snaps = data.get("snapshots", [])
        if status == "success":
            swarm_state.set_phase("SNAPSHOT_READY")
            swarm_state.set_snapshot(", ".join(snaps))
            swarm_state.add_log(
                f"AWS Snapshot created: {swarm_state.snapshot_name}", level="RESULT", agent="Snapshot"
            )
            logger.info(f"AWS Snapshot created: {swarm_state.snapshot_name}")

    elif tool_name == "create_gcp_snapshot":
        swarm_state.set_phase("SNAPSHOTTING")
        status = data.get("status", "unknown")
        snaps = data.get("snapshots", [])
        if status == "success":
            swarm_state.set_phase("SNAPSHOT_READY")
            swarm_state.set_snapshot(", ".join(snaps))
            swarm_state.add_log(
                f"GCP Snapshot created: {swarm_state.snapshot_name}", level="RESULT", agent="Snapshot"
            )
            logger.info(f"GCP Snapshot created: {swarm_state.snapshot_name}")

    elif tool_name == "delete_aws_snapshot":
        status = data.get("status", "unknown")
        if status == "complete":
            swarm_state.add_log(
                "AWS Snapshots cleaned up.", level="RESULT", agent="Snapshot"
            )
            logger.info("AWS Snapshots cleaned up.")

    elif tool_name == "delete_gcp_snapshot":
        status = data.get("status", "unknown")
        if status == "complete":
            swarm_state.add_log(
                "GCP Snapshots cleaned up.", level="RESULT", agent="Snapshot"
            )
            logger.info("GCP Snapshots cleaned up.")

    elif tool_name == "deploy_patch":
        swarm_state.set_phase("PATCHING")
        status = data.get("status", "unknown")
        pkg = data.get("package", "unknown")
        if status == "success":
            swarm_state.set_phase("PATCHED")
            swarm_state.add_log(
                f"Patch deployed: {pkg} ✓", level="RESULT", agent="Deployer"
            )
            logger.info(f"Patch deployed: {pkg} ✓")

    elif tool_name == "install_manual_package":
        swarm_state.set_phase("PATCHING")
        status = data.get("status", "unknown")
        pkg = data.get("package", "unknown")
        if status == "success":
            swarm_state.set_phase("PATCHED")
            swarm_state.add_log(
                f"Manual Patch deployed: {pkg} ✓", level="RESULT", agent="Deployer"
            )
            logger.info(f"Manual Patch deployed: {pkg} ✓")
        else:
            swarm_state.add_log(
                f"Manual Patch failed: {pkg} ❌", level="ERROR", agent="Deployer"
            )
            logger.error(f"Manual Patch failed: {pkg} ❌")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Pre-Execute Discovery (CSV + OS Detection)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _pre_execute_discovery(session: ClientSession) -> dict:
    """
    Pre-execute the deterministic discovery steps BEFORE the LLM takes over.
    1. Read the vulnerability CSV via MCP
    2. Detect the OS on the target via MCP
    Returns a context dict with all gathered information.
    """
    context = {
        "csv_data": None,
        "target_ip": None,
        "os_info": None,
        "vulnerabilities": [],
    }

    # ── Step 1: Read CSV ────────────────────────────────────────
    swarm_state.add_log(
        "🔍 Auto-Discovery 1/2: Reading vulnerability CSV…",
        level="ACTION", agent="Discovery",
    )
    logger.info("🔍 Auto-Discovery 1/2: Reading vulnerability CSV…")
    
    csv_abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vul_csv", "sec-1123.csv")
    csv_result = await call_mcp_tool(session, "read_vulnerability_csv", {
        "file_path": csv_abs_path,
    })
    logger.info(f"CSV Result: {csv_result}")

    try:
        csv_data = json.loads(csv_result)
        context["csv_data"] = csv_data
        vulns = csv_data.get("vulnerabilities", [])
        context["vulnerabilities"] = vulns

        if vulns:
            context["target_ip"] = vulns[0].get("ip", TARGET_HOST)
            swarm_state.add_log(
                f"CSV Ingested: {len(vulns)} vulnerability(s) for {context['target_ip']}",
                level="RESULT", agent="Discovery",
            )
            logger.info(f"CSV Ingested: {len(vulns)} vulnerability(s) for {context['target_ip']}")
        else:
            swarm_state.add_log(
                "No vulnerabilities found in CSV", level="WARN", agent="Discovery"
            )
            logger.warning("No vulnerabilities found in CSV")
            return context
    except json.JSONDecodeError:
        swarm_state.add_log(
            f"CSV parse error: {csv_result[:200]}", level="ERROR", agent="Discovery"
        )
        return context

    # ── Step 2: Detect OS ───────────────────────────────────────
    swarm_state.add_log(
        f"🔍 Auto-Discovery 2/2: Detecting OS on {context['target_ip']}…",
        level="ACTION", agent="Discovery",
    )
    logger.info(f"🔍 Auto-Discovery 2/2: Detecting OS on {context['target_ip']}…")
    swarm_state.set_phase("DETECTING")
    os_result = await call_mcp_tool(session, "detect_os", {
        "host": context["target_ip"],
        "user": TARGET_USER,
        "password": TARGET_PASSWORD,
        "port": TARGET_PORT,
        "key_path": TARGET_KEY_PATH,
    })

    try:
        os_data = json.loads(os_result)
        context["os_info"] = os_data
        
        if "error" in os_data:
            swarm_state.add_log(f"OS Detection failed: {os_data['error']}", level="ERROR", agent="Discovery")
            logger.error(f"OS Detection failed: {os_data['error']}")
            return context # Will be handled by run_pipeline
            
        _update_dashboard_from_tool(
            "detect_os",
            {"host": context["target_ip"], "port": TARGET_PORT},
            os_result,
        )
        swarm_state.add_log(
            f"OS Detected: {os_data.get('os_family', 'Unknown')} / {os_data.get('pkg_manager', 'unknown')}",
            level="RESULT", agent="Discovery",
        )
    except json.JSONDecodeError:
        swarm_state.add_log("OS detection parse error", level="ERROR", agent="Discovery")
        context["os_info"] = {"error": "JSON parse error from tool"}

    return context


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main Entrypoint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def main():
    """
    Main async entrypoint:
    1. Start the Rich dashboard
    2. Connect to MCP server via stdio
    3. Pre-execute CSV ingestion + OS detection
    4. Run the ReAct loop with enriched context
    """
    # ── Start Dashboard ─────────────────────────────────────────
    global dashboard
    dashboard = SentinelDashboard()
    dashboard.start()

    swarm_state.add_log("Sentinel Swarm initializing…", level="INFO", agent="System")
    swarm_state.set_footer("Connecting to MCP server…")

    # ── Configure LiteLLM ───────────────────────────────────────
    litellm.set_verbose = False

    # ── MCP Client Session ──────────────────────────────────────
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[MCP_SERVER_SCRIPT],
        env={**os.environ},
    )

    swarm_state.add_log(
        f"Launching MCP server: {MCP_SERVER_SCRIPT}", level="INFO", agent="MCP"
    )
    logger.info(f"Launching MCP server: {MCP_SERVER_SCRIPT}")

    try:
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize the MCP session
                await session.initialize()
                swarm_state.add_log(
                    "MCP session initialized", level="RESULT", agent="MCP"
                )

                # List available tools
                tools_response = await session.list_tools()
                tool_names = [t.name for t in tools_response.tools]
                swarm_state.set_mcp_status("Running", tool_names)
                swarm_state.add_log(
                    f"Tools available: {', '.join(tool_names)}",
                    level="TOOL", agent="MCP",
                )

                # Build OpenAI-compatible tool schemas
                tools_schema = build_tools_schema(tools_response.tools)

                # Inject the virtual consult_advisor tool (handled by coordinator)
                tools_schema.append({
                    "type": "function",
                    "function": {
                        "name": "consult_advisor",
                        "description": (
                            "Consult the Cloud Advisor (ChatGPT) for technical intelligence. "
                            "Ask generic questions about package versions, manual install steps, "
                            "or validation test commands. NEVER include IPs or credentials."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "prompt": {
                                    "type": "string",
                                    "description": "The anonymized technical question.",
                                }
                            },
                            "required": ["prompt"],
                        },
                    },
                })

                # Test LLM connectivity
                swarm_state.add_log(
                    f"Testing LLM: {LLM_MODEL}…", level="INFO", agent="LLM"
                )
                try:
                    test_kwargs = {}
                    if "ollama" in LLM_MODEL:
                        test_kwargs["num_ctx"] = OLLAMA_NUM_CTX
                        if OLLAMA_NUM_GPU >= 0:
                            test_kwargs["num_gpu"] = OLLAMA_NUM_GPU
                    test_resp = await asyncio.to_thread(
                        litellm.completion,
                        model=LLM_MODEL,
                        messages=[{"role": "user", "content": "Say 'ready'"}],
                        api_base=OLLAMA_BASE_URL,
                        max_tokens=10,
                        **test_kwargs,
                    )
                    swarm_state.set_model_status("Running")
                    swarm_state.add_log(
                        f"LLM online: {test_resp.choices[0].message.content.strip()}",
                        level="RESULT", agent="LLM",
                    )
                except Exception as e:
                    swarm_state.set_model_status("Error")
                    swarm_state.add_log(
                        f"LLM connection failed: {e}", level="ERROR", agent="LLM"
                    )
                    swarm_state.add_log(
                        "Ensure ollama is running with gemma4:e4b loaded",
                        level="WARN", agent="LLM",
                    )

                # ── Run the Deterministic Pipeline ──────────────
                swarm_state.set_footer("🚀 Pipeline starting…")

                final_answer = await run_pipeline(session)

                swarm_state.add_log(
                    "Mission complete.", level="RESULT", agent="System"
                )
                logger.success("Mission complete.")
                logger.info(f"Final summary:\n{final_answer}")

                # Keep dashboard alive for review
                swarm_state.set_footer(
                    "✅ Mission complete — press Ctrl+C to exit"
                )
                logger.info("Mission complete — press Ctrl+C to exit")
                try:
                    while True:
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    pass

    except FileNotFoundError:
        swarm_state.add_log(
            f"MCP server script not found: {MCP_SERVER_SCRIPT}",
            level="ERROR", agent="System",
        )
        logger.error(f"MCP server script not found: {MCP_SERVER_SCRIPT}")
    except Exception as e:
        swarm_state.add_log(
            f"Fatal error: {e}", level="ERROR", agent="System"
        )
        logger.error(f"Fatal: {e}\n{traceback.format_exc()}")
    finally:
        if dashboard:
            dashboard.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛡️ Sentinel Swarm shut down.")
