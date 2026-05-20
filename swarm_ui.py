"""
╔══════════════════════════════════════════════════════════════════╗
║  Sentinel Swarm Dashboard — Rich Terminal UI                   ║
║  Phase 1: Agentic AI Evolution for AI Cyber-Patch Sentinel     ║
╚══════════════════════════════════════════════════════════════════╝
"""

import time
import threading
import asyncio
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box

MODEL_NAME = "gemma4:e4b"
REFRESH_RATE = 4


class SwarmState:
    """Thread-safe shared state for the Sentinel dashboard."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reasoning_log: list[dict] = []
        self.max_log_entries: int = 200
        self.mcp_server_status: str = "Initializing"
        self.mcp_tools_registered: list[str] = []
        self.target_host: str = "—"
        self.target_port: int = 0
        self.detected_os: str = "—"
        self.detected_pkg_manager: str = "—"
        self.ssh_connected: bool = False
        self.current_phase: str = "IDLE"
        self.model_status: str = "Connecting"
        self.footer_message: str = "Awaiting orchestrator startup…"
        self.snapshot_name: str = "—"
        self.restart_required: bool = False
        
        # SSE Queue for web frontend
        self.sse_queue: Optional[asyncio.Queue] = None

    def set_sse_queue(self, queue: asyncio.Queue):
        with self._lock:
            self.sse_queue = queue

    def add_log(self, message: str, level: str = "INFO", agent: str = "Orchestrator"):
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "level": level, "agent": agent, "message": message,
        }
        with self._lock:
            self.reasoning_log.append(log_entry)
            if len(self.reasoning_log) > self.max_log_entries:
                self.reasoning_log = self.reasoning_log[-self.max_log_entries:]
            
            # If SSE queue exists, try to put the message in it
            if self.sse_queue:
                try:
                    # We need to handle the fact that add_log might be called from a sync thread
                    # while the queue is in an async loop.
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.call_soon_threadsafe(self.sse_queue.put_nowait, log_entry)
                except Exception:
                    pass

    def get_logs(self, last_n: int = 50) -> list[dict]:
        with self._lock:
            return list(self.reasoning_log[-last_n:])

    def set_mcp_status(self, status: str, tools: Optional[list[str]] = None):
        with self._lock:
            self.mcp_server_status = status
            if tools is not None:
                self.mcp_tools_registered = tools

    def set_target(self, host: str, port: int, os_family: str = "—",
                   pkg_manager: str = "—", connected: bool = False):
        with self._lock:
            self.target_host = host
            self.target_port = port
            self.detected_os = os_family
            self.detected_pkg_manager = pkg_manager
            self.ssh_connected = connected

    def set_phase(self, phase: str):
        with self._lock:
            self.current_phase = phase

    def set_model_status(self, status: str):
        with self._lock:
            self.model_status = status

    def set_footer(self, message: str):
        with self._lock:
            self.footer_message = message

    def set_snapshot(self, name: str):
        with self._lock:
            self.snapshot_name = name


swarm_state = SwarmState()


def get_layout() -> Layout:
    """Build the Rich Layout: Header | Left (Reasoning) + Right (MCP) | Footer."""
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )
    return layout


def _render_header() -> Panel:
    phase = swarm_state.current_phase
    phase_colors = {
        "IDLE": "dim white", "DETECTING": "cyan", "SCANNING": "yellow",
        "SCANNED": "green", "SNAPSHOTTING": "magenta", "SNAPSHOT_READY": "green",
        "PATCHING": "bold yellow", "PATCHED": "bold green", "VERIFIED": "bold green",
        "ERROR": "bold red",
    }
    header_text = Text.assemble(
        ("🛡️  Sentinel Swarm Active", "bold bright_cyan"), ("  │  ", "dim"),
        (f"Model: {MODEL_NAME}", "bright_magenta"), ("  │  ", "dim"),
        ("Native SSH Mode", "bright_green"), ("  │  ", "dim"),
        ("Phase: ", "dim"), (phase, f"bold {phase_colors.get(phase, 'white')}"),
        ("  │  ", "dim"), (datetime.now().strftime("%H:%M:%S"), "dim cyan"),
    )
    return Panel(Align.center(header_text), style="bright_cyan", box=box.HEAVY)


def _render_reasoning_log() -> Panel:
    logs = swarm_state.get_logs(last_n=40)
    if not logs:
        return Panel(Text("Awaiting agent activity…", style="dim italic"),
                     title="[bold cyan]🧠 Agent Reasoning Log[/]",
                     border_style="cyan", box=box.ROUNDED)

    table = Table(show_header=True, header_style="bold bright_cyan",
                  box=None, expand=True, padding=(0, 1))
    table.add_column("Time", style="dim cyan", width=8, no_wrap=True)
    table.add_column("Agent", style="bright_magenta", width=14, no_wrap=True)
    table.add_column("Event", ratio=1)

    level_styles = {"INFO": "white", "TOOL": "bright_yellow", "THINK": "bright_cyan",
                    "ACTION": "bright_green", "RESULT": "green", "WARN": "yellow",
                    "ERROR": "bold red", "SSH": "bright_blue"}
    level_icons = {"INFO": "ℹ️ ", "TOOL": "🔧", "THINK": "💭", "ACTION": "⚡",
                   "RESULT": "✅", "WARN": "⚠️ ", "ERROR": "❌", "SSH": "🔑"}

    for entry in logs:
        style = level_styles.get(entry["level"], "white")
        icon = level_icons.get(entry["level"], "•")
        table.add_row(entry["timestamp"], entry["agent"],
                      Text(f"{icon} {entry['message']}", style=style))

    return Panel(table, title="[bold cyan]🧠 Agent Reasoning Log[/]",
                 subtitle="[dim]Discovery → Scan → Snapshot → Patch[/]",
                 border_style="cyan", box=box.ROUNDED)


def _render_mcp_status() -> Panel:
    tbl = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    tbl.add_column("Key", style="dim", width=18)
    tbl.add_column("Value", style="bright_white")

    sc = {"Running": "bold green", "Initializing": "yellow",
          "Error": "bold red", "Connecting": "cyan"}

    tbl.add_row("MCP Server", Text(swarm_state.mcp_server_status,
                                   style=sc.get(swarm_state.mcp_server_status, "white")))
    tbl.add_row("Model", Text(f"ollama/{MODEL_NAME}", style="bright_magenta"))
    tbl.add_row("Model Status", Text(swarm_state.model_status,
                                     style=sc.get(swarm_state.model_status, "white")))
    tools = ", ".join(swarm_state.mcp_tools_registered) or "—"
    tbl.add_row("Tools", Text(tools, style="bright_yellow"))
    tbl.add_row("", "")
    tbl.add_row(Text("── Target ──", style="bold bright_cyan"), Text(""))
    tbl.add_row("Host", Text(f"{swarm_state.target_host}:{swarm_state.target_port}"))
    tbl.add_row("SSH", Text("● Connected" if swarm_state.ssh_connected else "○ Disconnected",
                            style="bold green" if swarm_state.ssh_connected else "dim red"))
    tbl.add_row("OS Family", Text(swarm_state.detected_os, style="bright_cyan"))
    tbl.add_row("Pkg Manager", Text(swarm_state.detected_pkg_manager, style="bright_yellow"))
    tbl.add_row("Snapshot ID", Text(swarm_state.snapshot_name, style="dim white"))
    tbl.add_row("", "")
    tbl.add_row(Text("── Pipeline ──", style="bold bright_cyan"), Text(""))
    tbl.add_row("Current Phase", Text(swarm_state.current_phase, style="bold bright_green"))

    return Panel(tbl, title="[bold magenta]📡 MCP Server & Connectivity[/]",
                 border_style="magenta", box=box.ROUNDED)


def _render_footer() -> Panel:
    return Panel(Text(f"  {swarm_state.footer_message}", style="bright_white"),
                 style="dim cyan", box=box.HEAVY)


class SentinelDashboard:
    """Manages the Rich Live display loop in a background thread."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._console = Console()

    def _render_loop(self):
        layout = get_layout()
        with Live(layout, console=self._console,
                  refresh_per_second=REFRESH_RATE, screen=True) as live:
            while self._running:
                layout["header"].update(_render_header())
                layout["left"].update(_render_reasoning_log())
                layout["right"].update(_render_mcp_status())
                layout["footer"].update(_render_footer())
                time.sleep(1 / REFRESH_RATE)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._render_loop,
                                        daemon=True, name="sentinel-dashboard")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    @property
    def is_running(self) -> bool:
        return self._running


if __name__ == "__main__":
    # Demo mode
    dashboard = SentinelDashboard()
    dashboard.start()
    swarm_state.set_mcp_status("Running",
        ["detect_os", "scan_target", "create_snapshot", "deploy_patch"])
    swarm_state.set_model_status("Running")

    demo_events = [
        ("Initializing MCP client session…", "INFO", "Orchestrator"),
        ("MCP Server 'Sentinel_Core' connected via stdio", "RESULT", "MCP"),
        ("Tools registered: detect_os, scan_target, create_snapshot, deploy_patch", "TOOL", "MCP"),
        ("User request: 'Audit and patch sandbox at localhost:2223'", "INFO", "User"),
        ("Thinking: Must detect OS first. Calling detect_os…", "THINK", "Orchestrator"),
        ("→ detect_os(host='127.0.0.1', user='root', port=2223)", "ACTION", "Discovery"),
        ("SSH connected to root@127.0.0.1:2223", "SSH", "Discovery"),
        ("OS detected: Debian (Ubuntu 22.04) — pkg_manager: apt", "RESULT", "Discovery"),
        ("→ scan_target(pkg_manager='apt')", "ACTION", "Scanner"),
        ("Found 3 upgradable packages (1 Critical)", "RESULT", "Scanner"),
        ("→ create_snapshot(os_family='Debian')", "ACTION", "Snapshot"),
        ("Snapshot created: /tmp/PRE_PATCH_SEC-1234.tar.gz", "RESULT", "Snapshot"),
        ("→ deploy_patch(package='libssl3', version='3.0.15-1')", "ACTION", "Deployer"),
        ("Patch deployed: libssl3 → 3.0.15-1 ✓", "RESULT", "Deployer"),
        ("Pipeline complete.", "RESULT", "Orchestrator"),
    ]

    try:
        for i, (msg, level, agent) in enumerate(demo_events):
            swarm_state.add_log(msg, level=level, agent=agent)
            logger.info(f"{msg} {level} {agent}")
            if "detect_os" in msg and level == "ACTION":
                swarm_state.set_phase("DETECTING")
            elif "OS detected" in msg:
                swarm_state.set_target("127.0.0.1", 2223, "Debian", "apt", True)
            elif "scan_target" in msg:
                swarm_state.set_phase("SCANNING")
            elif "upgradable" in msg:
                swarm_state.set_phase("SCANNED")
            elif "create_snapshot" in msg and level == "ACTION":
                swarm_state.set_phase("SNAPSHOTTING")
            elif "Snapshot created" in msg:
                swarm_state.set_phase("SNAPSHOT_READY")
            elif "deploy_patch" in msg and level == "ACTION":
                swarm_state.set_phase("PATCHING")
            elif "Patch deployed" in msg:
                swarm_state.set_phase("PATCHED")
            elif "Pipeline complete" in msg:
                swarm_state.set_phase("VERIFIED")
            swarm_state.set_footer(f"Step {i+1}/{len(demo_events)}: {msg[:60]}")
            time.sleep(1.2)
        swarm_state.set_footer("✅ Demo complete — press Ctrl+C to exit")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        dashboard.stop()
