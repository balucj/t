"""
╔══════════════════════════════════════════════════════════════════╗
║  MCP Sentinel Server — "Sentinel_Core"                         ║
║  The Tool Backbone with Native Paramiko SSH Execution          ║
║                                                                ║
║  Phase 1: Agentic AI Evolution for AI Cyber-Patch Sentinel     ║
║  Exposes detect_os, scan_target, create_snapshot, deploy_patch ║
║  as MCP tools callable by the Agent Coordinator.               ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import socket
import time
import traceback
from typing import Optional
from datetime import datetime, timezone

import paramiko
from mcp.server.fastmcp import FastMCP
from loguru import logger

# Cloud providers
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from google.cloud import compute_v1
    from google.oauth2 import service_account
    from google.api_core import exceptions as google_exceptions
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

# ── Initialise the MCP Server ──────────────────────────────────
mcp = FastMCP(
    "Sentinel_Core",
    instructions=(
        "AI Cyber-Patch Sentinel MCP backbone. Provides cross-platform "
        "OS detection, vulnerability scanning, snapshot creation, and "
        "surgical patch deployment via native SSH."
    ),
)

# ── Logger ──────────────────────────────────────────────────────
# Remove any existing handlers to avoid duplicates when imported by agent_coordinator
logger.remove()
logger.add(
    "agent_coordinator.log",
    rotation="5 MB",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {file}:{function}:{line} - {message}",
    level="DEBUG",
)

logger.info(f"Sentinel_Core starting. AWS Available: {AWS_AVAILABLE}, GCP Available: {GCP_AVAILABLE}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SSH Helper — connection factory with robust error handling
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _ssh_connect(
    host: str,
    user: str,
    key_path: Optional[str] = None,
    password: Optional[str] = None,
    port: int = 22,
    timeout: int = 30,
) -> paramiko.SSHClient:
    """
    Create and return a connected Paramiko SSHClient.

    Supports both key-based and password-based authentication.
    Raises a descriptive error on connection or auth failure.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = {
        "hostname": host,
        "port": port,
        "username": user,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
    }

    # Prefer key-based auth, fall back to password
    if key_path:
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key_path)
            connect_kwargs["pkey"] = pkey
        except paramiko.ssh_exception.SSHException:
            # Try other key types
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
                connect_kwargs["pkey"] = pkey
            except Exception:
                pkey = paramiko.ECDSAKey.from_private_key_file(key_path)
                connect_kwargs["pkey"] = pkey
    elif password:
        connect_kwargs["password"] = password
    else:
        # Attempt agent-based auth by default
        connect_kwargs["allow_agent"] = True
        connect_kwargs["look_for_keys"] = True

    try:
        client.connect(**connect_kwargs)
        logger.info(f"SSH connected → {user}@{host}:{port}")
        return client
    except paramiko.AuthenticationException as e:
        raise ConnectionError(
            f"Authentication failed for {user}@{host}:{port} — {e}"
        ) from e
    except (paramiko.SSHException, socket.error, socket.timeout) as e:
        raise ConnectionError(
            f"SSH connection failed to {host}:{port} — {e}"
        ) from e


def _ssh_exec(
    client: paramiko.SSHClient,
    command: str,
    timeout: int = 120,
) -> dict:
    """
    Execute a command over an established SSH session.

    Returns a dict with: exit_code, stdout, stderr, command, timestamp.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode("utf-8", errors="replace").strip()
        stderr_text = stderr.read().decode("utf-8", errors="replace").strip()

        logger.debug(
            f"CMD [{exit_code}]: {command[:80]}{'…' if len(command) > 80 else ''}"
        )
        return {
            "exit_code": exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "command": command,
            "timestamp": timestamp,
        }
    except socket.timeout:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "command": command,
            "timestamp": timestamp,
        }
    except Exception as exc:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Execution error: {exc}",
            "command": command,
            "timestamp": timestamp,
        }


# ── Global SSH Client Cache ───────────────────────────────────
_ssh_client_cache: dict[str, paramiko.SSHClient] = {}

def _get_cached_client(host: str, user: str, port: int = 22, key_path: str = "", password: str = "") -> paramiko.SSHClient:
    """Retrieve an existing SSH client from cache or create a new one."""
    cache_key = f"{user}@{host}:{port}"
    
    if cache_key in _ssh_client_cache:
        client = _ssh_client_cache[cache_key]
        if client.get_transport() and client.get_transport().is_active():
            logger.debug(f"Reusing cached SSH connection for {cache_key}")
            return client
        else:
            logger.info(f"Cached connection for {cache_key} is dead. Reconnecting...")
            try:
                client.close()
            except:
                pass
            del _ssh_client_cache[cache_key]

    client = _ssh_connect(host, user, key_path=key_path or None, password=password or None, port=port)
    _ssh_client_cache[cache_key] = client
    return client

def _ssh_run(
    host: str,
    user: str,
    key_path: Optional[str],
    password: Optional[str],
    command: str,
    port: int = 22,
    timeout: int = 120,
) -> dict:
    """
    High-level helper: uses cached connection if available.
    """
    client = _get_cached_client(host, user, port, key_path or "", password or "")
    return _ssh_exec(client, command, timeout=timeout)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool 1 — detect_os
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def detect_os(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
) -> str:
    """
    Detect the operating system family and package manager of a remote host.

    Connects via SSH and probes for Linux (/etc/os-release), macOS (sw_vers),
    or Windows (systeminfo). Returns a JSON object with:
      - os_family:       "Debian", "RHEL", "Arch", "macOS", "Windows", or "Unknown"
      - os_name:         Human-readable distro name
      - os_version:      Version string
      - pkg_manager:     "apt", "dnf", "yum", "pacman", "brew", "choco", "winget", or "unknown"
      - kernel:          Kernel version string
      - hostname:        Remote hostname
      - raw_os_release:  Full /etc/os-release contents (Linux only)
    """
    logger.info(f"[detect_os] Probing {user}@{host}:{port}")

    result = {
        "os_family": "Unknown",
        "os_name": "Unknown",
        "os_version": "",
        "pkg_manager": "unknown",
        "kernel": "",
        "hostname": "",
        "raw_os_release": "",
    }

    try:
        client = _get_cached_client(
            host, user,
            port=port,
            key_path=key_path,
            password=password,
        )
    except Exception as e:
        result["error"] = str(e)
        return json.dumps(result, indent=2)

    try:
        # ── Hostname ────────────────────────────────────────────
        r = _ssh_exec(client, "hostname")
        result["hostname"] = r["stdout"].strip()

        # ── Try Linux first: /etc/os-release ────────────────────
        r = _ssh_exec(client, "cat /etc/os-release 2>/dev/null")
        if r["exit_code"] == 0 and r["stdout"]:
            result["raw_os_release"] = r["stdout"]
            os_info = _parse_os_release(r["stdout"])

            result["os_name"] = os_info.get("PRETTY_NAME", os_info.get("NAME", "Linux"))
            result["os_version"] = os_info.get("VERSION_ID", "")
            id_like = os_info.get("ID_LIKE", "").lower()
            os_id = os_info.get("ID", "").lower()

            # Classify family + package manager
            if os_id in ("debian", "ubuntu", "linuxmint", "pop", "kali") or "debian" in id_like:
                result["os_family"] = "Debian"
                result["pkg_manager"] = "apt"
            elif os_id in ("rhel", "centos", "fedora", "rocky", "alma", "ol") or "rhel" in id_like or "fedora" in id_like:
                result["os_family"] = "RHEL"
                # Prefer dnf, fall back to yum
                dnf_check = _ssh_exec(client, "which dnf 2>/dev/null")
                result["pkg_manager"] = "dnf" if dnf_check["exit_code"] == 0 else "yum"
            elif os_id in ("arch", "manjaro", "endeavouros") or "arch" in id_like:
                result["os_family"] = "Arch"
                result["pkg_manager"] = "pacman"
            elif os_id in ("suse", "opensuse-leap", "opensuse-tumbleweed") or "suse" in id_like:
                result["os_family"] = "SUSE"
                result["pkg_manager"] = "zypper"
            elif os_id == "alpine":
                result["os_family"] = "Alpine"
                result["pkg_manager"] = "apk"
            else:
                result["os_family"] = "Linux"
                result["pkg_manager"] = _detect_pkg_manager_fallback(client)

            # Kernel version
            kr = _ssh_exec(client, "uname -r")
            result["kernel"] = kr["stdout"].strip()

        else:
            # ── Try macOS ───────────────────────────────────────
            r = _ssh_exec(client, "sw_vers 2>/dev/null")
            if r["exit_code"] == 0 and "ProductName" in r["stdout"]:
                result["os_family"] = "macOS"
                result["pkg_manager"] = "brew"
                for line in r["stdout"].splitlines():
                    if "ProductName" in line:
                        result["os_name"] = line.split(":", 1)[-1].strip()
                    if "ProductVersion" in line:
                        result["os_version"] = line.split(":", 1)[-1].strip()
                kr = _ssh_exec(client, "uname -r")
                result["kernel"] = kr["stdout"].strip()
            else:
                # ── Try Windows ─────────────────────────────────
                r = _ssh_exec(client, "systeminfo 2>nul", timeout=60)
                if r["exit_code"] == 0 and "OS Name" in r["stdout"]:
                    result["os_family"] = "Windows"
                    for line in r["stdout"].splitlines():
                        if "OS Name" in line:
                            result["os_name"] = line.split(":", 1)[-1].strip()
                        if "OS Version" in line:
                            result["os_version"] = line.split(":", 1)[-1].strip()
                    # Determine Windows package manager
                    choco = _ssh_exec(client, "choco --version 2>nul")
                    winget = _ssh_exec(client, "winget --version 2>nul")
                    if choco["exit_code"] == 0:
                        result["pkg_manager"] = "choco"
                    elif winget["exit_code"] == 0:
                        result["pkg_manager"] = "winget"
                    else:
                        result["pkg_manager"] = "unknown"

        logger.info(
            f"[detect_os] Result: {result['os_family']} / {result['pkg_manager']} "
            f"on {result['hostname']}"
        )
        return json.dumps(result, indent=2)

    except Exception as exc:
        logger.error(f"[detect_os] Error: {exc}\n{traceback.format_exc()}")
        result["error"] = str(exc)
        return json.dumps(result, indent=2)


def _parse_os_release(text: str) -> dict:
    """Parse /etc/os-release KEY=VALUE pairs into a dict."""
    data = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, val = line.partition("=")
            data[key.strip()] = val.strip().strip('"')
    return data


def _detect_pkg_manager_fallback(client: paramiko.SSHClient) -> str:
    """Brute-force detect package manager by checking binary availability."""
    for mgr in ("apt", "dnf", "yum", "pacman", "zypper", "apk", "emerge"):
        r = _ssh_exec(client, f"which {mgr} 2>/dev/null")
        if r["exit_code"] == 0:
            return mgr
    return "unknown"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool 2 — scan_target
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def scan_target(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
    pkg_manager: str = "apt",
) -> str:
    """
    Audit outdated/upgradable packages on a remote host using the detected
    package manager. Returns a JSON object containing a list of vulnerabilities
    (each with package name, current version, available version, and severity).

    Supported package managers: apt, dnf, yum, pacman, apk, zypper, choco, winget.
    """
    logger.info(f"[scan_target] Scanning {user}@{host}:{port} with pkg_manager={pkg_manager}")

    scan_result = {
        "host": host,
        "port": port,
        "pkg_manager": pkg_manager,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "vulnerabilities": [],
        "total_upgradable": 0,
        "raw_output": "",
    }

    # Build the audit command per package manager
    audit_commands: dict[str, str] = {
        "apt": (
            "apt-get update -qq 2>/dev/null && "
            "apt list --upgradable 2>/dev/null | grep -v '^Listing'"
        ),
        "dnf": "dnf check-update --quiet 2>/dev/null || true",
        "yum": "yum check-update --quiet 2>/dev/null || true",
        "pacman": "pacman -Qu 2>/dev/null",
        "apk": "apk version -l '<' 2>/dev/null",
        "zypper": "zypper list-updates 2>/dev/null",
        "choco": "choco outdated --limit-output 2>nul",
        "winget": "winget upgrade --include-unknown 2>nul",
    }

    cmd = audit_commands.get(pkg_manager)
    if not cmd:
        scan_result["error"] = f"Unsupported package manager: {pkg_manager}"
        return json.dumps(scan_result, indent=2)

    try:
        r = _ssh_run(
            host, user,
            key_path=key_path or None,
            password=password or None,
            command=cmd,
            port=port,
            timeout=180,
        )
        scan_result["raw_output"] = r["stdout"]

        # Parse output into structured vulnerability records
        vulns = _parse_upgradable(r["stdout"], pkg_manager)
        scan_result["vulnerabilities"] = vulns
        scan_result["total_upgradable"] = len(vulns)

        logger.info(f"[scan_target] Found {len(vulns)} upgradable packages on {host}")
        return json.dumps(scan_result, indent=2)

    except ConnectionError as e:
        scan_result["error"] = str(e)
        return json.dumps(scan_result, indent=2)
    except Exception as exc:
        logger.error(f"[scan_target] Error: {exc}\n{traceback.format_exc()}")
        scan_result["error"] = str(exc)
        return json.dumps(scan_result, indent=2)


def _parse_upgradable(output: str, pkg_manager: str) -> list[dict]:
    """Parse package manager output into a list of vulnerability dicts."""
    vulns = []

    if not output.strip():
        return vulns

    if pkg_manager == "apt":
        # Format: "package/codename current_ver upgradable to: new_ver"
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("WARNING") or line.startswith("N:"):
                continue
            try:
                # e.g. "libssl3/jammy-security 3.0.15-1 amd64 [upgradable from: 3.0.10-1]"
                pkg_part = line.split("/")[0]
                parts = line.split()
                current_ver = ""
                new_ver = ""
                for i, p in enumerate(parts):
                    if p == "from:":
                        current_ver = parts[i + 1].rstrip("]") if i + 1 < len(parts) else ""
                    if "/" in parts[0] and len(parts) > 1:
                        new_ver = parts[1]
                vulns.append({
                    "package": pkg_part,
                    "current_version": current_ver,
                    "available_version": new_ver,
                    "severity": _estimate_severity(pkg_part),
                })
            except (IndexError, ValueError):
                continue

    elif pkg_manager in ("dnf", "yum"):
        # Format: "package.arch  version  repo"
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                pkg_name = parts[0].rsplit(".", 1)[0] if "." in parts[0] else parts[0]
                vulns.append({
                    "package": pkg_name,
                    "current_version": "installed",
                    "available_version": parts[1] if len(parts) > 1 else "",
                    "severity": _estimate_severity(pkg_name),
                })

    elif pkg_manager == "pacman":
        # Format: "package old_ver -> new_ver"
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "->":
                vulns.append({
                    "package": parts[0],
                    "current_version": parts[1],
                    "available_version": parts[3],
                    "severity": _estimate_severity(parts[0]),
                })

    elif pkg_manager == "choco":
        # Format: "package|current|available|pinned"
        for line in output.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 3:
                vulns.append({
                    "package": parts[0],
                    "current_version": parts[1],
                    "available_version": parts[2],
                    "severity": _estimate_severity(parts[0]),
                })

    else:
        # Generic: one package per line
        for line in output.strip().splitlines():
            line = line.strip()
            if line:
                vulns.append({
                    "package": line.split()[0] if line.split() else line,
                    "current_version": "unknown",
                    "available_version": "available",
                    "severity": "Medium",
                })

    return vulns


def _estimate_severity(pkg_name: str) -> str:
    """Heuristic severity estimation based on package name."""
    critical_keywords = ("openssl", "libssl", "openssh", "kernel", "sudo", "glibc", "libc6")
    high_keywords = ("curl", "libcurl", "nginx", "apache", "python3", "git", "bash")

    name_lower = pkg_name.lower()
    for kw in critical_keywords:
        if kw in name_lower:
            return "Critical"
    for kw in high_keywords:
        if kw in name_lower:
            return "High"
    return "Medium"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool 2.5 — run_vulnerability_scan
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def run_vulnerability_scan(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
    package: str = "",
    remediation_version: str = "",
    pkg_manager: str = "apt",
) -> str:
    """
    Check if a specific package is installed and if the remediation version
    is available via the native package manager.
    """
    logger.info(f"[run_vulnerability_scan] Checking {package} on {host}")
    
    result = {
        "package": package,
        "remediation_version": remediation_version,
        "is_installed": False,
        "is_upgradable": False,
        "available_version": "",
        "status": "unknown"
    }

    try:
        client = _ssh_connect(host, user, key_path=key_path or None, password=password or None, port=port)
    except ConnectionError as e:
        return json.dumps({"error": str(e)})

    try:
        if pkg_manager == "winget":
            # Try exact match first
            cmd = f'winget list --name "{package}" --exact'
            logger.info(f"command to search {cmd}",cmd)
            r = _ssh_exec(client, cmd)
            found = False
            logger.info(f"the result of the finding {r}")
            if r["exit_code"] == 0 and package.lower() in r["stdout"].lower():
                result["is_installed"] = True
                found = True
                # Parse winget output for version info
                lines = r["stdout"].splitlines()
                for line in lines:
                    if package.lower() in line.lower():
                        parts = [p.strip() for p in line.split()]
                        if len(parts) >= 4:
                            # Typical winget format: Name Id Version Available Source
                            # Check if we have enough columns
                            if len(parts) >= 5:
                                # Name(0) Id(1) Version(2) Available(3) Source(4)
                                result['id'] = parts[2]
                                result["available_version"] = parts[3]
                                current_version = parts[2]
                                if result["available_version"] != current_version and result["available_version"].lower() not in ["unknown", ""]:
                                    result["is_upgradable"] = True
                            elif len(parts) == 4:
                                # Name Id Version Available
                                result["available_version"] = parts[2]
                                current_version = parts[1]
                                if result["available_version"] != current_version and result["available_version"].lower() not in ["unknown", ""]:
                                    result["is_upgradable"] = True
            else:
                # Fallback: try without --exact flag for partial matches
                r2 = _ssh_exec(client, f'winget list "{package}"')
                if r2["exit_code"] == 0 and package.lower() in r2["stdout"].lower():
                    result["is_installed"] = True
                    found = True
                    # Parse output from fallback search
                    lines = r2["stdout"].splitlines()
                    for line in lines:
                        if package.lower() in line.lower():
                            parts = [p.strip() for p in line.split()]
                            if len(parts) >= 4:
                                if len(parts) >= 5:
                                    result["available_version"] = parts[3]
                                    current_version = parts[2]
                                elif len(parts) == 4:
                                    result["available_version"] = parts[2]
                                    current_version = parts[1]
                                if result["available_version"] != current_version and result["available_version"].lower() not in ["unknown", ""]:
                                    result["is_upgradable"] = True

            # If still not found via name, try by ID (sometimes winget uses different ID than name)
            if not found:
                r3 = _ssh_exec(client, f'winget list --id "{package}" --exact')
                if r3["exit_code"] == 0 and package.lower() in r3["stdout"].lower():
                    result["is_installed"] = True
                    found = True
                    lines = r3["stdout"].splitlines()
                    for line in lines:
                        if package.lower() in line.lower():
                            parts = [p.strip() for p in line.split()]
                            if len(parts) >= 4:
                                if len(parts) >= 5:
                                    result["available_version"] = parts[3]
                                    current_version = parts[2]
                                elif len(parts) == 4:
                                    result["available_version"] = parts[2]
                                    current_version = parts[1]
                                if result["available_version"] != current_version and result["available_version"].lower() not in ["unknown", ""]:
                                    result["is_upgradable"] = True
            
        elif pkg_manager == "apt":
            r = _ssh_exec(client, f"dpkg-query -W -f='${{Version}}' {package} 2>/dev/null")
            if r["exit_code"] == 0:
                result["is_installed"] = True
                # Check if update is available via apt-cache
                upd = _ssh_exec(client, f"apt-cache policy {package} | grep Candidate")
                if upd["stdout"]:
                    result["available_version"] = upd["stdout"].split(":")[-1].strip()
                    if result["available_version"] != r["stdout"].strip():
                        result["is_upgradable"] = True

        elif pkg_manager in ("dnf", "yum"):
            r = _ssh_exec(client, f"rpm -q {package}")
            if r["exit_code"] == 0:
                result["is_installed"] = True
                upd = _ssh_exec(client, f"{pkg_manager} check-update {package} --quiet")
                if upd["exit_code"] == 100: # Found updates
                    result["is_upgradable"] = True
                    # Extract version from check-update output
                    for line in upd["stdout"].splitlines():
                        if package in line:
                            result["available_version"] = line.split()[1]
        
        # Determine Status
        if not result["is_installed"]:
            result["status"] = "NOT_INSTALLED"
        elif result["is_upgradable"] and (not remediation_version or remediation_version in result["available_version"]):
            result["status"] = "INSTALLED_UPDATABLE"
        else:
            result["status"] = "INSTALLED_MANUAL_REQUIRED"

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"[run_vulnerability_scan] Error: {e}")
        return json.dumps({"error": str(e)})
    finally:
        pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool 3 — create_snapshot
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def create_snapshot(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
    os_family: str = "Debian",
    snapshot_label: str = "",
) -> str:
    """
    Create a pre-patch safety snapshot/backup on the remote host.

    - Linux (Debian/RHEL/Arch/etc.): tar -czf /tmp/PRE_PATCH_<label>.tar.gz
      backing up /etc, /usr/share/doc, and package manager state.
    - Windows: Creates a System Restore Point via PowerShell.

    Returns a JSON object with snapshot path, size, and status.
    """
    label = snapshot_label or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    logger.info(f"[create_snapshot] Creating snapshot '{label}' on {host}:{port} (OS: {os_family})")

    snapshot_result = {
        "host": host,
        "os_family": os_family,
        "label": label,
        "status": "pending",
        "snapshot_path": "",
        "size_bytes": "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        client = _ssh_connect(
            host, user,
            key_path=key_path or None,
            password=password or None,
            port=port,
        )
    except ConnectionError as e:
        snapshot_result["status"] = "failed"
        snapshot_result["error"] = str(e)
        return json.dumps(snapshot_result, indent=2)

    try:
        if os_family.lower() in ("windows",):
            # Windows: create restore point via PowerShell
            cmd = (
                'powershell -Command "Checkpoint-Computer '
                f"-Description 'SentinelPatch_{label}' "
                '-RestorePointType MODIFY_SETTINGS"'
            )
            r = _ssh_exec(client, cmd, timeout=120)
            snapshot_result["snapshot_path"] = f"SystemRestore:SentinelPatch_{label}"
        else:
            # Linux: tar-based backup of critical directories
            snapshot_path = f"/tmp/PRE_PATCH_{label}.tar.gz"

            # Determine directories to back up based on package manager state
            backup_dirs = "/etc"
            if os_family.lower() in ("debian",):
                backup_dirs += " /var/lib/dpkg/status"
            elif os_family.lower() in ("rhel",):
                backup_dirs += " /var/lib/rpm"

            cmd = (
                f"tar -czf {snapshot_path} "
                f"--exclude='/tmp/*.tar.gz' "
                f"{backup_dirs} 2>/dev/null && "
                f"stat -c '%s' {snapshot_path} 2>/dev/null || "
                f"echo 'SNAPSHOT_CREATED'"
            )
            r = _ssh_exec(client, cmd, timeout=300)
            snapshot_result["snapshot_path"] = snapshot_path

            # Try to get size
            if r["stdout"].strip().isdigit():
                snapshot_result["size_bytes"] = r["stdout"].strip()
            else:
                # Get size separately
                sr = _ssh_exec(client, f"stat -c '%s' {snapshot_path} 2>/dev/null || echo '0'")
                snapshot_result["size_bytes"] = sr["stdout"].strip()

        if r["exit_code"] == 0 or "SNAPSHOT_CREATED" in r.get("stdout", ""):
            snapshot_result["status"] = "success"
            logger.info(f"[create_snapshot] Snapshot created: {snapshot_result['snapshot_path']}")
        else:
            snapshot_result["status"] = "partial"
            snapshot_result["stderr"] = r.get("stderr", "")
            logger.warning(f"[create_snapshot] Partial snapshot: {r.get('stderr', '')}")

        return json.dumps(snapshot_result, indent=2)

    except Exception as exc:
        logger.error(f"[create_snapshot] Error: {exc}\n{traceback.format_exc()}")
        snapshot_result["status"] = "failed"
        snapshot_result["error"] = str(exc)
        return json.dumps(snapshot_result, indent=2)
    finally:
        pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool 4 — deploy_patch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def deploy_patch(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
    pkg_manager: str = "apt",
    package: str = "",
    version: str = "",
    install_commands: list[str] = [],
    verify_command: str = "",
) -> str:
    """
    Deploy a surgical patch to a package on the remote host.
    Can use default package manager logic OR custom commands provided by the Advisor.
    """
    logger.info(
        f"[deploy_patch] Deploying {package} on {host}:{port} "
        f"via {pkg_manager} (Custom commands: {len(install_commands)})"
    )

    patch_result = {
        "host": host,
        "package": package,
        "target_version": version,
        "pkg_manager": pkg_manager,
        "status": "pending",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "install_output": [],
        "verification": {},
    }

    try:
        client = _get_cached_client(host, user, port=port, key_path=key_path, password=password)
    except Exception as e:
        patch_result["status"] = "failed"
        patch_result["error"] = str(e)
        return json.dumps(patch_result, indent=2)

    try:
        # ── Step 1: Determine commands ──────────────────────────
        actual_install_cmds = []
        actual_verify_cmd = verify_command

        if install_commands:
            actual_install_cmds = install_commands
        else:
            if not package:
                patch_result["status"] = "failed"
                patch_result["error"] = "No package or custom commands specified"
                return json.dumps(patch_result, indent=2)
            
            i_cmd, v_cmd = _build_patch_commands(pkg_manager, package, version)
            if not i_cmd:
                patch_result["status"] = "failed"
                patch_result["error"] = f"Unsupported package manager: {pkg_manager}"
                return json.dumps(patch_result, indent=2)
            actual_install_cmds = [i_cmd]
            if not actual_verify_cmd:
                actual_verify_cmd = v_cmd

        # ── Step 2: Update package index (Linux only, skipped for custom commands) ──
        if not install_commands and pkg_manager in ("apt", "dnf", "yum", "apk", "zypper"):
            update_cmds = {
                "apt": "apt-get update -qq",
                "dnf": "dnf makecache -q",
                "yum": "yum makecache fast -q",
                "apk": "apk update",
                "zypper": "zypper refresh -q",
            }
            _ssh_exec(client, update_cmds[pkg_manager], timeout=120)

        # ── Step 3: Execute Installation commands ───────────────
        all_success = True
        for cmd in actual_install_cmds:
            logger.info(f"[deploy_patch] Executing command: {cmd}")
            r = _ssh_exec(client, cmd, timeout=300)
            patch_result["install_output"].append({
                "command": cmd,
                "exit_code": r["exit_code"],
                "stdout": r["stdout"],
                "stderr": r["stderr"],
            })
            if r["exit_code"] != 0:
                all_success = False
                break

        # ── Step 4: Verify installation ─────────────────────────
        if actual_verify_cmd:
            v = _ssh_exec(client, actual_verify_cmd, timeout=30)
            patch_result["verification"] = {
                "exit_code": v["exit_code"],
                "stdout": v["stdout"].strip(),
            }

        if all_success:
            patch_result["status"] = "success"
            logger.info(f"[deploy_patch] Patch operation completed for {package}")
        else:
            patch_result["status"] = "failed"
            logger.error(f"[deploy_patch] Patch operation failed for {package}")

        return json.dumps(patch_result, indent=2)

    except Exception as exc:
        logger.error(f"[deploy_patch] Error: {exc}\n{traceback.format_exc()}")
        patch_result["status"] = "failed"
        patch_result["error"] = str(exc)
        return json.dumps(patch_result, indent=2)



def _build_patch_commands(
    pkg_manager: str, package: str, version: str
) -> tuple[str, str]:
    logger.info("Building the patch commands")
    """
    Return (install_cmd, verify_cmd) for the given package manager.
    """
    ver_suffix = f"={version}" if version else ""

    commands: dict[str, tuple[str, str]] = {
        "apt": (
            f"DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y {package}{ver_suffix}",
            f"dpkg-query -W -f='${{Version}}' {package} 2>/dev/null",
        ),
        "dnf": (
            f"dnf upgrade -y {package}{'-' + version if version else ''}",
            f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {package} 2>/dev/null",
        ),
        "yum": (
            f"yum update -y {package}{'-' + version if version else ''}",
            f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {package} 2>/dev/null",
        ),
        "pacman": (
            f"pacman -S --noconfirm {package}",
            f"pacman -Q {package} 2>/dev/null | awk '{{print $2}}'",
        ),
        "apk": (
            f"apk add --upgrade {package}{ver_suffix}",
            f"apk info -v {package} 2>/dev/null",
        ),
        "zypper": (
            f"zypper install -y {package}{ver_suffix}",
            f"rpm -q --qf '%{{VERSION}}-%{{RELEASE}}' {package} 2>/dev/null",
        ),
        "choco": (
            f'choco upgrade "{package}" {"--version=" + version if version else ""} -y --no-progress',
            f'choco list --local-only "{package}" --limit-output 2>nul',
        ),
        "winget": (
            f'winget upgrade --id "{package}" {"--version " + version if version else ""} --accept-package-agreements --accept-source-agreements',
            f'winget list --id "{package}" 2>nul',
        ),
    }
    logger.info("Commands: ", commands.get(pkg_manager, ("", "")))
    return commands.get(pkg_manager, ("", ""))


@mcp.tool()
def install_manual_package(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
    install_commands: list[str] = [],
    package: str = "",
) -> str:
    """
    Perform a manual installation of a remediated package using custom commands.
    Typically used when the package manager (apt/dnf) doesn't have the version.
    """
    logger.info(f"[install_manual_package] Installing {package} on {host}")
    results = []
    
    try:
        client = _ssh_connect(host, user, key_path=key_path or None, password=password or None, port=port)
    except ConnectionError as e:
        return json.dumps({"error": str(e)})

    try:
        for cmd in install_commands:
            r = _ssh_exec(client, cmd, timeout=300)
            results.append({
                "command": cmd,
                "exit_code": r["exit_code"],
                "stdout": r["stdout"],
                "stderr": r["stderr"]
            })
            if r["exit_code"] != 0:
                return json.dumps({
                    "status": "failed",
                    "package": package,
                    "failed_command": cmd,
                    "results": results
                }, indent=2)
                
        return json.dumps({
            "status": "success",
            "package": package,
            "results": results
        }, indent=2)
    finally:
        pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool 5 — check_package_usage
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def check_package_usage(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
    package: str = "",
) -> str:
    """
    Check where a specific package is being used in the system.
    Probes running processes (lsof), systemd services, and binary locations.
    """
    logger.info(f"[check_package_usage] Probing {package} on {host}:{port}")
    usage_result = {
        "package": package,
        "running_processes": [],
        "systemd_services": [],
        "binary_paths": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        client = _ssh_connect(host, user, key_path=key_path or None, password=password or None, port=port)
    except ConnectionError as e:
        return json.dumps({"error": str(e)})

    try:
        # 1. Binary locations
        r_which = _ssh_exec(client, f"which -a {package} 2>/dev/null || whereis {package}")
        usage_result["binary_paths"] = [p.strip() for p in r_which["stdout"].split() if "/" in p]

        # 2. Running processes using the package (via lsof if available, else ps)
        r_lsof = _ssh_exec(client, f"lsof -t $(which {package} 2>/dev/null) 2>/dev/null | xargs ps -fp 2>/dev/null")
        if r_lsof["stdout"]:
            usage_result["running_processes"] = r_lsof["stdout"].splitlines()

        # 3. Systemd services
        r_systemd = _ssh_exec(client, f"systemctl list-units --type=service --state=active | grep -i {package}")
        usage_result["systemd_services"] = [line.strip() for line in r_systemd["stdout"].splitlines() if line.strip()]

        return json.dumps(usage_result, indent=2)
    finally:
        pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MCP Tool 6 — run_custom_test
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def run_custom_test(
    host: str,
    user: str,
    key_path: str = "",
    password: str = "",
    port: int = 22,
    test_command: str = "",
    description: str = "Custom validation test",
) -> str:
    """
    Execute a custom validation test (command) on the remote host.
    Used to verify that a patch didn't break functionality.
    """
    logger.info(f"[run_custom_test] Running: {description} on {host}")
    try:
        r = _ssh_run(host, user, key_path=key_path or None, password=password or None, command=test_command, port=port)
        return json.dumps({
            "description": description,
            "exit_code": r["exit_code"],
            "stdout": r["stdout"],
            "stderr": r["stderr"],
            "status": "passed" if r["exit_code"] == 0 else "failed"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


import boto3
from botocore.exceptions import ClientError


@mcp.tool()
def read_vulnerability_csv(file_path: str) -> str:
    """
    Read a CSV file containing vulnerability reports.
    Extracts IP, package name, current version, and remediation version.
    """
    import csv
    import re
    import os
    
    logger.info(f"[read_vulnerability_csv] Reading: {file_path}")
    results = []
    
    if not os.path.exists(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})
        
    try:
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("IP", "").strip()
                desc = row.get("Description", "")
                
                # Regex to extract Package, Vulnerable version, and Remediation version
                pkg_match = re.search(r"Package:\s*([^|]+)", desc)
                vuln_match = re.search(r"Status:\s*Vulnerable\s*\(v?([^)]+)\)", desc)
                remedy_match = re.search(r"Remediation:\s*Update\s*to\s*v?([^| ]+)", desc)
                
                results.append({
                    "ip": ip,
                    "package": pkg_match.group(1).strip() if pkg_match else "Unknown",
                    "current_version": vuln_match.group(1).strip() if vuln_match else "Unknown",
                    "remediation_version": remedy_match.group(1).strip() if remedy_match else "Unknown",
                    "raw_description": desc
                })
        
        return json.dumps({"vulnerabilities": results}, indent=2)
    except Exception as e:
        logger.error(f"[read_vulnerability_csv] Error: {e}")
        return json.dumps({"error": str(e)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  AWS Snapshot Tools
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def create_aws_snapshot(
    host: str,
    aws_access_key: str = "",
    aws_secret_key: str = "",
    region: str = "us-east-1",
    description: str = "Sentinel Pre-Patch Snapshot",
) -> str:
    """
    Find an AWS EC2 instance by its public/private IP (host) and create 
    EBS snapshots of all its attached volumes for a safety backup.
    """
    logger.info(f"[create_aws_snapshot] Target: {host} in {region}")
    
    try:
        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=aws_access_key or None,
            aws_secret_access_key=aws_secret_key or None,
            region_name=region
        )
        
        # 1. Find the Instance ID from the IP address
        filters = [
            {'Name': 'network-interface.addresses.private-ip-address', 'Values': [host]},
            {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
        ]
        # Also check public IP if private doesn't match
        response = ec2.describe_instances(Filters=filters)
        if not response['Reservations']:
            filters[0] = {'Name': 'ip-address', 'Values': [host]}
            response = ec2.describe_instances(Filters=filters)
            
        if not response['Reservations']:
            return json.dumps({"error": f"No EC2 instance found with IP {host}"})
            
        instance = response['Reservations'][0]['Instances'][0]
        instance_id = instance['InstanceId']
        volumes = [v['Ebs']['VolumeId'] for v in instance['BlockDeviceMappings']]
        
        # 2. Create snapshots for all volumes
        snapshot_ids = []
        for vol_id in volumes:
            snap = ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"{description} (Instance: {instance_id}, Vol: {vol_id})",
                TagSpecifications=[{
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'SentinelBackup', 'Value': 'true'},
                        {'Key': 'InstanceId', 'Value': instance_id},
                        {'Key': 'OriginalVolumeId', 'Value': vol_id}
                    ]
                }]
            )
            snapshot_ids.append(snap['SnapshotId'])
            
        logger.info(f"[AWS] Created {len(snapshot_ids)} snapshots for {instance_id}")
        return json.dumps({
            "status": "success",
            "instance_id": instance_id,
            "snapshots": snapshot_ids,
            "region": region,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, indent=2)

    except ClientError as e:
        logger.error(f"[AWS Error] {e}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def delete_aws_snapshot(
    snapshot_ids: list[str],
    aws_access_key: str = "",
    aws_secret_key: str = "",
    region: str = "us-east-1",
) -> str:
    """
    Delete one or more EBS snapshots by their Snapshot IDs.
    """
    logger.info(f"[delete_aws_snapshot] Deleting snapshots: {snapshot_ids}")
    
    try:
        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=aws_access_key or None,
            aws_secret_access_key=aws_secret_key or None,
            region_name=region
        )
        
        results = []
        for snap_id in snapshot_ids:
            try:
                ec2.delete_snapshot(SnapshotId=snap_id)
                results.append({"snapshot_id": snap_id, "status": "deleted"})
            except ClientError as e:
                results.append({"snapshot_id": snap_id, "status": "failed", "error": str(e)})
                
        return json.dumps({
            "status": "complete",
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, indent=2)

    except ClientError as e:
        logger.error(f"[AWS Delete Error] {e}")
        return json.dumps({"error": str(e)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  GCP Snapshot Tools
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
def create_gcp_snapshot(
    host: str,
    project_id: str = "",
    zone: str = "us-central1-a",
    credentials_path: str = "",
    description: str = "Sentinel Pre-Patch Snapshot",
) -> str:
    """
    Find a GCP Compute Engine instance by its internal/external IP (host) and
    create disk snapshots of all its attached disks for a safety backup.
    """
    if not GCP_AVAILABLE:
        return json.dumps({"error": "GCP dependencies not installed. Install google-cloud-compute."})

    logger.info(f"[create_gcp_snapshot] Target: {host} in project {project_id} zone {zone}")

    try:
        # Load credentials
        if credentials_path:
            credentials = service_account.Credentials.from_service_account_file(credentials_path)
        else:
            # Use Application Default Credentials
            credentials = None

        # Initialize compute client
        compute_client = compute_v1.InstancesClient(credentials=credentials)

        # 1. Find the Instance from the IP address
        # Note: GCP API doesn't have a direct IP lookup, so we need to list instances and match
        # For simplicity in PoC, we'll assume the host matches the instance name or we need to enhance this
        request = compute_v1.AggregatedListInstancesRequest()
        request.project = project_id

        agg_list = compute_client.aggregated_list(request=request)

        instance = None
        for zone_response, response in agg_list:
            if response.instances:
                for inst in response.instances:
                    # Check if any network interface matches the host IP
                    for network_interface in inst.network_interfaces:
                        for access_config in network_interface.access_configs:
                            if access_config.nat_i_p == host or network_interface.network_i_p == host:
                                instance = inst
                                break
                        if instance:
                            break
                    if instance:
                        break
                if instance:
                    break

        if not instance:
            return json.dumps({"error": f"No GCP instance found with IP {host}"})

        instance_name = instance.name
        instance_zone = instance.zone.split('/')[-1]  # Extract zone name from full path

        # 2. Create snapshots for all disks
        snapshot_ids = []
        disks_client = compute_v1.DisksClient(credentials=credentials)
        
        for disk in instance.disks:
            disk_name = disk.source.split('/')[-1]  # Extract disk name from full path

            # Create snapshot resource
            snapshot_resource = compute_v1.Snapshot()
            # Generate a unique name for the snapshot (must be lowercase, start with letter)
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            # Ensure it starts with a letter and is lowercase
            sanitized_disk = "".join(c for c in disk_name if c.isalnum() or c == "-").lower()[:20]
            snapshot_resource.name = f"sentinel-{sanitized_disk}-{timestamp_str}"
            snapshot_resource.description = f"{description} (Instance: {instance_name}, Disk: {disk_name})"

            # Use DisksClient to create a snapshot of the disk
            operation = disks_client.create_snapshot(
                project=project_id,
                zone=instance_zone,
                disk=disk_name,
                snapshot_resource=snapshot_resource
            )

            # Wait for operation to complete (simplified for PoC)
            # In production, you'd want to properly wait for the operation
            snapshot_ids.append(snapshot_resource.name)

        logger.info(f"[GCP] Created {len(snapshot_ids)} snapshots for {instance_name}")
        return json.dumps({
            "status": "success",
            "instance_name": instance_name,
            "instance_zone": instance_zone,
            "snapshots": snapshot_ids,
            "project_id": project_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, indent=2)

    except Exception as e:
        logger.error(f"[GCP Error] {e}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def delete_gcp_snapshot(
    snapshot_names: list[str],
    project_id: str = "",
    credentials_path: str = "",
) -> str:
    """
    Delete one or more GCP snapshots by their snapshot names.
    """
    if not GCP_AVAILABLE:
        return json.dumps({"error": "GCP dependencies not installed. Install google-cloud-compute."})

    logger.info(f"[delete_gcp_snapshot] Deleting snapshots: {snapshot_names}")

    try:
        # Load credentials
        if credentials_path:
            credentials = service_account.Credentials.from_service_account_file(credentials_path)
        else:
            # Use Application Default Credentials
            credentials = None

        # Initialize snapshot client
        snapshot_client = compute_v1.SnapshotsClient(credentials=credentials)

        results = []
        for snapshot_name in snapshot_names:
            try:
                operation = snapshot_client.delete(
                    project=project_id,
                    snapshot=snapshot_name
                )
                results.append({"snapshot_name": snapshot_name, "status": "deleted"})
            except Exception as e:
                results.append({"snapshot_name": snapshot_name, "status": "failed", "error": str(e)})

        return json.dumps({
            "status": "complete",
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, indent=2)

    except Exception as e:
        logger.error(f"[GCP Delete Error] {e}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def rollback_gcp_snapshot(
    host: str,
    snapshot_names: list[str],
    project_id: str = "",
    zone: str = "us-central1-a",
    credentials_path: str = "",
) -> str:
    """
    Revert a GCP Compute Engine instance to a previous state using disk snapshots.
    Stops the instance, replaces disks with new ones created from snapshots, and restarts the instance.
    """
    if not GCP_AVAILABLE:
        return json.dumps({"error": "GCP dependencies not installed. Install google-cloud-compute."})

    logger.info(f"[rollback_gcp_snapshot] Rolling back {host} using {snapshot_names}")

    try:
        # Load credentials
        if credentials_path:
            credentials = service_account.Credentials.from_service_account_file(credentials_path)
        else:
            # Use Application Default Credentials
            credentials = None

        # Initialize compute client
        compute_client = compute_v1.InstancesClient(credentials=credentials)
        disks_client = compute_v1.DisksClient(credentials=credentials)

        # 1. Find the Instance from the IP address
        request = compute_v1.AggregatedListInstancesRequest()
        request.project = project_id

        agg_list = compute_client.aggregated_list(request=request)

        instance = None
        for zone_response, response in agg_list:
            if response.instances:
                for inst in response.instances:
                    # Check if any network interface matches the host IP
                    for network_interface in inst.network_interfaces:
                        for access_config in network_interface.access_configs:
                            if access_config.nat_i_p == host or network_interface.network_i_p == host:
                                instance = inst
                                break
                        if instance:
                            break
                    if instance:
                        break
                if instance:
                    break

        if not instance:
            return json.dumps({"error": f"No GCP instance found with IP {host}"})

        instance_name = instance.name
        instance_zone = instance.zone.split('/')[-1]  # Extract zone name from full path

        # 2. Stop the instance
        logger.info(f"[rollback_gcp_snapshot] Stopping instance {instance_name}")
        operation = compute_client.stop(
            project=project_id,
            zone=instance_zone,
            instance=instance_name
        )

        # Wait for operation to complete
        while not operation.done():
            time.sleep(1)

        # 3. Get current disks
        instance_disks = instance.disks

        # 4. For each disk, create a new disk from snapshot and replace
        for i, disk in enumerate(instance_disks):
            source_disk = disk.source.split('/')[-1]  # Extract disk name from full path
            device_name = disk.device_name
            is_boot = disk.boot
            auto_delete = disk.auto_delete

            # Find corresponding snapshot for this disk
            if i < len(snapshot_names):
                snapshot_name = snapshot_names[i]

                logger.info(f"[rollback_gcp_snapshot] Creating disk from snapshot {snapshot_name}")

                # Get snapshot details
                snapshot_client = compute_v1.SnapshotsClient(credentials=credentials)
                snapshot = snapshot_client.get(
                    project=project_id,
                    snapshot=snapshot_name
                )

                # Create disk from snapshot
                disk_resource = compute_v1.Disk()
                disk_resource.name = f"{source_disk}-rollback-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
                disk_resource.source_snapshot = snapshot.self_link
                disk_resource.size_gb = snapshot.disk_size_gb
                # Omit type_ to use default or consider fetching from original disk

                operation = disks_client.insert(
                    project=project_id,
                    zone=instance_zone,
                    disk_resource=disk_resource
                )

                # Wait for operation to complete
                while not operation.done():
                    time.sleep(1)

                new_disk_name = disk_resource.name

                # Detach old disk
                logger.info(f"[rollback_gcp_snapshot] Detaching disk {source_disk}")
                operation = compute_client.detach_disk(
                    project=project_id,
                    zone=instance_zone,
                    instance=instance_name,
                    device_name=device_name
                )

                # Wait for operation to complete
                while not operation.done():
                    time.sleep(1)

                # Attach new disk
                logger.info(f"[rollback_gcp_snapshot] Attaching new disk {new_disk_name} as {device_name} (Boot: {is_boot})")
                attached_disk = compute_v1.AttachedDisk()
                attached_disk.source = f"projects/{project_id}/zones/{instance_zone}/disks/{new_disk_name}"
                attached_disk.device_name = device_name
                attached_disk.boot = is_boot
                attached_disk.auto_delete = auto_delete

                operation = compute_client.attach_disk(
                    project=project_id,
                    zone=instance_zone,
                    instance=instance_name,
                    attached_disk_resource=attached_disk
                )

                # Wait for operation to complete
                while not operation.done():
                    time.sleep(1)

        # 5. Start the instance
        logger.info(f"[rollback_gcp_snapshot] Starting instance {instance_name}")
        operation = compute_client.start(
            project=project_id,
            zone=instance_zone,
            instance=instance_name
        )

        # Wait for operation to complete
        while not operation.done():
            time.sleep(1)

        logger.info(f"[rollback_gcp_snapshot] Rollback completed for instance {instance_name}")
        return json.dumps({
            "status": "success",
            "message": f"Successfully rolled back instance {instance_name} using {len(snapshot_names)} snapshots.",
            "instance_name": instance_name
        }, indent=2)

    except Exception as e:
        logger.error(f"[rollback_gcp_snapshot] Error: {e}\n{traceback.format_exc()}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def rollback_aws_snapshot(
    host: str,
    snapshot_ids: list[str],
    aws_access_key: str = "",
    aws_secret_key: str = "",
    region: str = "us-east-1",
) -> str:
    """
    Revert an EC2 instance to a previous state using EBS snapshots.
    Stops the instance, detaches current volumes, creates new ones
    from snapshots, attaches them, and restarts the instance.
    """
    logger.info(f"[rollback_aws_snapshot] Rolling back {host} using {snapshot_ids}")

    try:
        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=aws_access_key or None,
            aws_secret_access_key=aws_secret_key or None,
            region_name=region
        )

        # 1. Find the Instance ID from the IP address
        filters = [
            {'Name': 'network-interface.addresses.private-ip-address', 'Values': [host]},
            {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
        ]
        # Also check public IP if private doesn't match
        response = ec2.describe_instances(Filters=filters)
        if not response['Reservations']:
            filters[0] = {'Name': 'ip-address', 'Values': [host]}
            response = ec2.describe_instances(Filters=filters)

        if not response['Reservations']:
            return json.dumps({"error": f"No EC2 instance found with IP {host}"})

        instance = response['Reservations'][0]['Instances'][0]
        instance_id = instance['InstanceId']

        # 2. Stop the instance
        logger.info(f"[rollback_aws_snapshot] Stopping instance {instance_id}")
        ec2.stop_instances(InstanceIds=[instance_id])

        # Wait for instance to stop
        waiter = ec2.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=[instance_id])

        # 3. Get current block device mappings
        block_device_mappings = instance['BlockDeviceMappings']

        # 4. For each volume, create a new volume from snapshot and replace
        for i, mapping in enumerate(block_device_mappings):
            volume_id = mapping['Ebs']['VolumeId']
            device_name = mapping['DeviceName']

            # Find corresponding snapshot for this volume (by checking tags)
            # We'll assume snapshot_ids are in the same order as volumes for simplicity
            if i < len(snapshot_ids):
                snapshot_id = snapshot_ids[i]

                logger.info(f"[rollback_aws_snapshot] Creating volume from snapshot {snapshot_id}")

                # Get snapshot details to know volume size and type
                snapshot_response = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
                snapshot = snapshot_response['Snapshots'][0]

                # Create volume from snapshot
                volume_response = ec2.create_volume(
                    SnapshotId=snapshot_id,
                    AvailabilityZone=instance['Placement']['AvailabilityZone'],
                    VolumeType=snapshot.get('VolumeType', 'gp2'),
                    Size=snapshot['VolumeSize']
                )
                new_volume_id = volume_response['VolumeId']

                # Wait for volume to be available
                waiter = ec2.get_waiter('volume_available')
                waiter.wait(VolumeIds=[new_volume_id])

                # Detach old volume
                logger.info(f"[rollback_aws_snapshot] Detaching volume {volume_id}")
                ec2.detach_volume(VolumeId=volume_id, Force=True)

                # Wait for detachment
                waiter = ec2.get_waiter('volume_available')
                waiter.wait(VolumeIds=[volume_id])

                # Attach new volume
                logger.info(f"[rollback_aws_snapshot] Attaching new volume {new_volume_id} as {device_name}")
                ec2.attach_volume(
                    VolumeId=new_volume_id,
                    InstanceId=instance_id,
                    Device=device_name
                )

                # Wait for attachment
                waiter = ec2.get_waiter('volume_in_use')
                waiter.wait(VolumeIds=[new_volume_id])

        # 5. Start the instance
        logger.info(f"[rollback_aws_snapshot] Starting instance {instance_id}")
        ec2.start_instances(InstanceIds=[instance_id])

        # Wait for instance to start
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])

        logger.info(f"[rollback_aws_snapshot] Rollback completed for instance {instance_id}")
        return json.dumps({
            "status": "success",
            "message": f"Successfully rolled back instance {instance_id} using {len(snapshot_ids)} snapshots.",
            "instance_id": instance_id
        }, indent=2)

    except ClientError as e:
        logger.error(f"[rollback_aws_snapshot] AWS Error: {e}")
        return json.dumps({"error": str(e)})
    except Exception as exc:
        logger.error(f"[rollback_aws_snapshot] Error: {exc}\n{traceback.format_exc()}")
        return json.dumps({"error": str(exc)})


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Entrypoint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    logger.info("Starting Sentinel_Core MCP Server via stdio transport…")
    mcp.run(transport="stdio")
