import asyncio
import json
import os
import sys
import traceback
from typing import Optional, List
from datetime import datetime, timezone

from fastapi import FastAPI, Request, UploadFile, File, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sse_starlette.sse import EventSourceResponse
from loguru import logger

# Import your existing swarm logic
from swarm_ui import swarm_state
from agent_coordinator import (
    MCP_SERVER_SCRIPT, 
    TARGET_HOST, TARGET_USER, TARGET_PORT, TARGET_PASSWORD, TARGET_KEY_PATH,
    run_pipeline, build_tools_schema, OLLAMA_NUM_CTX, OLLAMA_NUM_GPU,
    LLM_MODEL, OLLAMA_BASE_URL, LLM_MAX_TOKENS, OPENAI_API_KEY
)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import litellm
from dotenv import load_dotenv
load_dotenv()  # Load variables from .env

# Base path for Nginx reverse proxy
BASE_PATH = os.getenv("BASE_PATH", "").rstrip("/")
if BASE_PATH and not BASE_PATH.startswith("/"):
    BASE_PATH = "/" + BASE_PATH

app = FastAPI(
    title="AI Cyber-Patch Sentinel Web",
    root_path=BASE_PATH
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Shared MCP session
mcp_session: Optional[ClientSession] = None
mcp_task: Optional[asyncio.Task] = None
sse_queue = asyncio.Queue()
csv_uploaded = False

# Path to the CSV file
CSV_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vul_csv", "sec-1123.csv")
CLOUD_PROVIDER = os.getenv("CLOUD_PROVIDER", "AWS").upper()

# Initialize swarm state with SSE queue
swarm_state.set_sse_queue(sse_queue)

async def mcp_worker():
    """Background worker to keep the MCP session alive with auto-reconnect."""
    global mcp_session
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[MCP_SERVER_SCRIPT],
        env={**os.environ},
    )
    
    while True:
        swarm_state.add_log("Launching MCP server...", level="INFO", agent="MCP")
        try:
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    mcp_session = session
                    
                    # Register tools in state
                    tools_response = await session.list_tools()
                    tool_names = [t.name for t in tools_response.tools]
                    swarm_state.set_mcp_status("Running", tool_names)
                    swarm_state.add_log(f"MCP Session Ready. Tools: {', '.join(tool_names)}", level="RESULT", agent="MCP")
                    
                    # Test LLM connectivity
                    try:
                        test_kwargs = {}
                        if "ollama" in LLM_MODEL:
                            test_kwargs["num_ctx"] = OLLAMA_NUM_CTX
                            if OLLAMA_NUM_GPU >= 0:
                                test_kwargs["num_gpu"] = OLLAMA_NUM_GPU
                        
                        await asyncio.to_thread(
                            litellm.completion,
                            model=LLM_MODEL,
                            messages=[{"role": "user", "content": "Say 'ready'"}],
                            api_base=OLLAMA_BASE_URL,
                            max_tokens=10,
                            **test_kwargs,
                        )
                        swarm_state.set_model_status("Running")
                    except Exception as e:
                        swarm_state.set_model_status("Error")
                        swarm_state.add_log(f"LLM connection failed: {e}", level="ERROR", agent="LLM")

                    # Keep alive until cancelled or session lost
                    while True:
                        await asyncio.sleep(5)
                        # Optional: Add a heartbeat check here if needed
                        
        except Exception as e:
            mcp_session = None
            swarm_state.set_mcp_status("Error")
            swarm_state.add_log(f"MCP Worker Error: {e}. Retrying in 5s...", level="ERROR", agent="MCP")
            logger.error(f"MCP Worker Error: {e}\n{traceback.format_exc()}")
            await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    global mcp_task
    mcp_task = asyncio.create_task(mcp_worker())

@app.on_event("shutdown")
async def shutdown_event():
    if mcp_task:
        mcp_task.cancel()

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse(
        request=request, 
        name="index.html", 
        context={"base_path": BASE_PATH}
    )

@app.get("/api/stream")
async def stream():
    async def event_generator():
        while True:
            # Check for new logs in the queue
            log_entry = await sse_queue.get()
            # Format as expected by script.js (it looks for data.log)
            # data.log should be a string like "[AGENT] message"
            formatted_log = f"[{log_entry['agent']}] {log_entry['message']}"
            yield {
                "data": json.dumps({"log": formatted_log})
            }

    return EventSourceResponse(event_generator())

@app.get("/api/status")
async def get_status():
    return JSONResponse(
        content={
            "phase": swarm_state.current_phase,
            "host": swarm_state.target_host,
            "os": swarm_state.detected_os,
            "pkg_mgr": swarm_state.detected_pkg_manager,
            "connected": swarm_state.ssh_connected,
            "snapshot": swarm_state.snapshot_name,
            "restart_required": swarm_state.restart_required,
            "csv_uploaded": csv_uploaded
        },
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    )

@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    if not csv_uploaded:
        return JSONResponse(content={"vulnerabilities": []}, headers={"Cache-Control": "no-store"})
    
    try:
        import csv
        import re
        vulnerabilities = []
        if not os.path.exists(CSV_FILE_PATH):
            return {"vulnerabilities": []}
            
        with open(CSV_FILE_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                desc = row.get("Description", "")
                pkg_match = re.search(r"Package:\s*([^|]+)", desc)
                remedy_match = re.search(r"Remediation:\s*Update\s*to\s*v?([^| ]+)", desc)
                
                vulnerabilities.append({
                    "id": i,
                    "package": pkg_match.group(1).strip() if pkg_match else "Unknown",
                    "version": remedy_match.group(1).strip() if remedy_match else "latest",
                    "cve": row.get("IP", "N/A"),
                    "severity": "High"
                })
        return JSONResponse(
            content={"vulnerabilities": vulnerabilities},
            headers={"Cache-Control": "no-store"}
        )
    except Exception as e:
        logger.error(f"Error reading vulnerabilities: {e}")
        return {"error": str(e), "vulnerabilities": []}

@app.post("/api/reset")
async def reset_session():
    global csv_uploaded
    csv_uploaded = False
    swarm_state.current_phase = "IDLE"
    swarm_state.target_host = "—"
    swarm_state.detected_os = "—"
    swarm_state.detected_pkg_manager = "—"
    swarm_state.snapshot_name = "—"
    swarm_state.restart_required = False
    swarm_state.ssh_connected = False
    
    if os.path.exists(CSV_FILE_PATH):
        try:
            os.remove(CSV_FILE_PATH)
        except:
            pass
            
    swarm_state.add_log("Session reset by user.", level="INFO", agent="System")
    return {"status": "reset"}

@app.post("/api/fix")
async def fix_issue(request: Request, background_tasks: BackgroundTasks):
    global csv_uploaded
    if not mcp_session:
        return {"error": "MCP session not ready"}
    
    if not csv_uploaded:
        return {"error": "No vulnerability report uploaded. Please upload a CSV first."}
    
    # Check for target_index in request body
    target_index = None
    try:
        body = await request.json()
        target_index = body.get("target_index")
    except:
        pass # Handle empty body
    
    swarm_state.set_phase("IDLE")
    background_tasks.add_task(run_pipeline, mcp_session, target_index)
    return {"status": "started"}

@app.post("/api/schedule-restart")
async def schedule_restart(request: Request):
    data = await request.json()
    time = data.get("datetime")
    swarm_state.add_log(f"Restart scheduled for: {time}", level="INFO", agent="System")
    return {"status": "scheduled", "time": time}

async def run_rollback_task(mcp_session: ClientSession, provider: str):
    try:
        swarm_state.set_phase("ROLLING_BACK")
        swarm_state.add_log("Initiating rollback...", level="ACTION", agent="System")
        
        host = swarm_state.target_host
        if not host or host == "—":
            host = TARGET_HOST or "127.0.0.1"
            
        logger.info(f"Initiating rollback process for host: {host} (Provider: {provider})")

        # Get snapshot names from swarm state
        snapshot_names = swarm_state.snapshot_name
        logger.info(f"Snapshot names from state: {snapshot_names}")

        if not snapshot_names or snapshot_names == "—":
            swarm_state.add_log("No snapshot available for rollback", level="ERROR", agent="System")
            logger.error("Rollback aborted: No snapshot available in swarm_state")
            swarm_state.set_phase("IDLE")
            return

        # Convert comma-separated snapshot names to list
        snapshot_list = [s.strip() for s in snapshot_names.split(",")] if snapshot_names else []
        
        if provider == "AWS":
            logger.info(f"Calling rollback_aws_snapshot for host {host} with snapshots {snapshot_list}")
            swarm_state.add_log(f"Calling AWS rollback for {len(snapshot_list)} snapshot(s)", level="ACTION", agent="System")

            result = await mcp_session.call_tool("rollback_aws_snapshot", {
                "host": host,
                "snapshot_ids": snapshot_list,
                "aws_access_key": os.getenv("AWS_ACCESS_KEY_ID", ""),
                "aws_secret_key": os.getenv("AWS_SECRET_ACCESS_KEY", ""),
                "region": os.getenv("AWS_DEFAULT_REGION", "eu-north-1")
            })

            output = ""
            if hasattr(result, "content") and result.content:
                output = "\n".join([block.text for block in result.content if hasattr(block, "text")])
            else:
                output = str(result)
            
            logger.info(f"AWS Rollback Result: {output}")
            try:
                result_data = json.loads(output)
            except:
                result_data = {"message": output}

            if "error" in result_data:
                swarm_state.add_log(f"Rollback failed: {result_data['error']}", level="ERROR", agent="System")
            else:
                swarm_state.add_log(f"Rollback completed: {result_data.get('message', 'Success')}", level="RESULT", agent="System")

                # NEW: Post-Rollback Application Verification
                swarm_state.add_log("Verifying application state after rollback...", level="THINK", agent="System")
                await asyncio.sleep(15) 

                try:
                    verify_res = await mcp_session.call_tool("run_custom_test", {
                        "host": host, "user": TARGET_USER, "password": TARGET_PASSWORD, "port": TARGET_PORT,
                        "test_command": "systemctl is-active nginx apache2 mysql docker || netstat -tuln | grep -E ':(80|443)'",
                        "description": "Application recovery check"
                    })
                    v_output = "\n".join([b.text for b in verify_res.content if hasattr(b, "text")]) if hasattr(verify_res, "content") else str(verify_res)
                    v_data = json.loads(v_output)

                    if v_data.get("status") == "passed":
                        swarm_state.add_log(f"Application recovery verified: {v_data.get('stdout')[:100]}", level="RESULT", agent="System")
                    else:
                        swarm_state.add_log("Application not yet responsive. Manual check suggested.", level="WARN", agent="System")
                except Exception as e:
                    logger.warning(f"Recovery check skipped: {e}")
                # NEW: Post-Rollback Application Verification
                swarm_state.add_log("Verifying application state after rollback...", level="THINK", agent="System")
                await asyncio.sleep(15) # Give the VM time to boot and services to start

                try:
                    # Extract result text correctly from CallToolResult
                    verify_res = await mcp_session.call_tool("run_custom_test", {
                        "host": host, "user": TARGET_USER, "password": TARGET_PASSWORD, "port": TARGET_PORT,
                        "test_command": "systemctl is-active nginx apache2 mysql docker || netstat -tuln | grep -E ':(80|443)'",
                        "description": "Application recovery check"
                    })
                    v_output = "\n".join([b.text for b in verify_res.content if hasattr(b, "text")]) if hasattr(verify_res, "content") else str(verify_res)
                    v_data = json.loads(v_output)

                    if v_data.get("status") == "passed":
                        swarm_state.add_log(f"Application recovery verified: {v_data.get('stdout')[:100]}", level="RESULT", agent="System")
                    else:
                        swarm_state.add_log("Application not yet responsive. Manual check suggested.", level="WARN", agent="System")
                except Exception as e:
                    logger.warning(f"Recovery check skipped: {e}")
        elif provider == "GCP":
            logger.info(f"Calling rollback_gcp_snapshot for host {host} with snapshots {snapshot_list}")
            swarm_state.add_log(f"Calling GCP rollback for {len(snapshot_list)} snapshot(s)", level="ACTION", agent="System")

            result = await mcp_session.call_tool("rollback_gcp_snapshot", {
                "host": host,
                "snapshot_names": snapshot_list,
                "project_id": os.getenv("GCP_PROJECT_ID", ""),
                "zone": os.getenv("GCP_ZONE", "us-central1-a"),
                "credentials_path": os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
            })

            output = ""
            if hasattr(result, "content") and result.content:
                output = "\n".join([block.text for block in result.content if hasattr(block, "text")])
            else:
                output = str(result)
            
            logger.info(f"GCP Rollback Result: {output}")
            try:
                result_data = json.loads(output)
            except:
                result_data = {"message": output}

            if "error" in result_data:
                swarm_state.add_log(f"Rollback failed: {result_data['error']}", level="ERROR", agent="System")
            else:
                swarm_state.add_log(f"Rollback completed: {result_data.get('message', 'Success')}", level="RESULT", agent="System")
        else:
            swarm_state.add_log(f"Unsupported cloud provider for rollback: {provider}", level="ERROR", agent="System")
            logger.error(f"Unsupported cloud provider: {provider}")

    except Exception as e:
        error_msg = f"Exception during rollback task: {str(e)}"
        swarm_state.add_log(error_msg, level="ERROR", agent="System")
        logger.error(f"{error_msg}\n{traceback.format_exc()}")
    finally:
        swarm_state.set_phase("IDLE")

@app.post("/api/rollback")
async def rollback(background_tasks: BackgroundTasks):
    if not mcp_session:
        logger.error("Rollback requested but MCP session is not ready")
        return {"error": "MCP session not ready"}

    # Sanitize CLOUD_PROVIDER
    provider = CLOUD_PROVIDER.split("#")[0].strip().upper()
    
    logger.info(f"Scheduling rollback task for provider: {provider}")
    background_tasks.add_task(run_rollback_task, mcp_session, provider)
    
    return {"status": "rollback_started"}

@app.post("/api/upload")
async def upload_csv(file: UploadFile = File(...)):
    global csv_uploaded
    # Ensure vul_csv directory exists
    os.makedirs(os.path.dirname(CSV_FILE_PATH), exist_ok=True)
    
    with open(CSV_FILE_PATH, "wb") as buffer:
        buffer.write(await file.read())
    
    csv_uploaded = True
    swarm_state.add_log(f"CSV uploaded and updated: {file.filename}", level="INFO", agent="User")
    return {"filename": file.filename, "status": "uploaded"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
