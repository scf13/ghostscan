#!/usr/bin/env python3
"""
GhostScan - Safe Parallel Executor
Replaces bare subprocess calls with:
  - Per-tool timeout
  - Configurable retry with backoff
  - Failure isolation (one tool crash never breaks the chain)
  - Parallel execution with dependency graph
  - Live output streaming
  - Resource limits (max concurrent, CPU throttle)
"""

import subprocess
import threading
import time
import os
import signal
import queue
import concurrent.futures
from typing import Callable, Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from modules.utils import log, Colors


class TaskState(Enum):
    PENDING   = auto()
    RUNNING   = auto()
    SUCCESS   = auto()
    FAILED    = auto()
    TIMEOUT   = auto()
    SKIPPED   = auto()
    CANCELLED = auto()


@dataclass
class ToolResult:
    tool:       str
    cmd:        list
    returncode: int = -1
    stdout:     str = ""
    stderr:     str = ""
    state:      TaskState = TaskState.PENDING
    elapsed:    float = 0.0
    attempts:   int = 0
    error:      str = ""

    @property
    def success(self) -> bool:
        return self.state == TaskState.SUCCESS

    @property
    def timed_out(self) -> bool:
        return self.state == TaskState.TIMEOUT


@dataclass
class Task:
    """A single tool execution task."""
    name:       str
    cmd:        list
    timeout:    int             = 300
    retries:    int             = 2
    retry_wait: float           = 5.0
    depends_on: list            = field(default_factory=list)
    on_success: Optional[Callable] = None
    on_failure: Optional[Callable] = None
    critical:   bool            = False   # if True and fails → stop the group
    env:        dict            = field(default_factory=dict)
    cwd:        str             = None
    live:       bool            = False   # stream stdout live

    def __post_init__(self):
        self.state  = TaskState.PENDING
        self.result = None


# Per-tool sensible timeouts (seconds)
TOOL_TIMEOUTS = {
    "nmap":         600,
    "masscan":      180,
    "gobuster":     300,
    "ffuf":         300,
    "feroxbuster":  300,
    "dirb":         300,
    "nikto":        600,
    "sqlmap":       480,
    "hydra":        600,
    "medusa":       600,
    "john":         900,
    "hashcat":     1800,
    "nuclei":       600,
    "wpscan":       300,
    "dnsrecon":     180,
    "amass":        300,
    "sublist3r":    180,
    "theHarvester": 120,
    "whatweb":       60,
    "wafw00f":       60,
    "sslscan":       60,
    "testssl":      120,
    "sslyze":        60,
    "enum4linux":   180,
    "crackmapexec": 120,
    "snmpwalk":      60,
    "onesixtyone":   60,
    "commix":       300,
    "xsstrike":     180,
    "wfuzz":        300,
}

DEFAULT_TIMEOUT = 300
MAX_RETRIES     = 2
RETRY_BACKOFF   = [5, 15, 30]   # seconds between retries


class SafeExecutor:
    """
    Thread-safe, fault-tolerant executor.
    All external tool calls go through here.

    Usage:
        ex = SafeExecutor(config, scope_enforcer)
        result = ex.run("nmap", ["nmap", "-sT", target])
        results = ex.run_parallel([task1, task2, task3])
    """

    def __init__(self, config: dict, scope=None):
        self.config    = config
        self.scope     = scope          # ScopeEnforcer instance
        self.verbose   = config.get("verbose", False)
        self.max_workers = config.get("threads", 10)
        self._lock     = threading.Lock()
        self._results: Dict[str, ToolResult] = {}
        self._cancelled = threading.Event()

    # ── SINGLE TOOL RUN ───────────────────────────────────────────────────────

    def run(self, tool: str, cmd: list,
            timeout: int = None,
            retries: int = None,
            env: dict = None,
            cwd: str = None,
            live: bool = False) -> ToolResult:
        """
        Run a single tool safely.
        Never raises — always returns a ToolResult.
        """
        timeout  = timeout  or TOOL_TIMEOUTS.get(tool, DEFAULT_TIMEOUT)
        retries  = retries  if retries is not None else MAX_RETRIES
        result   = ToolResult(tool=tool, cmd=cmd)

        # Scope check on target arguments
        if self.scope:
            try:
                self.scope.wrap_cmd(cmd)
            except Exception as e:
                result.state = TaskState.CANCELLED
                result.error = str(e)
                log(f"    🚫 Scope block: {tool} — {e}", Colors.BOLD_RED)
                return result

        # Retry loop
        for attempt in range(retries + 1):
            result.attempts = attempt + 1
            if self._cancelled.is_set():
                result.state = TaskState.CANCELLED
                return result

            t0 = time.time()
            try:
                result = self._execute(tool, cmd, timeout, env, cwd, live, result)
                result.elapsed = time.time() - t0

                if result.state == TaskState.SUCCESS:
                    self._store(tool, result)
                    return result

                if result.state == TaskState.TIMEOUT:
                    log(f"    ⏱ {tool} timed out after {timeout}s (attempt {attempt+1}/{retries+1})", Colors.YELLOW)
                    if attempt < retries:
                        wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF)-1)]
                        log(f"    ↻ Retrying in {wait}s...", Colors.DIM)
                        time.sleep(wait)
                    continue

                # Non-zero exit
                if result.returncode != 0 and attempt < retries:
                    wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF)-1)]
                    if self.verbose:
                        log(f"    ↻ {tool} failed (rc={result.returncode}), retry in {wait}s", Colors.DIM)
                    time.sleep(wait)
                    continue

                break  # final attempt or success

            except Exception as e:
                result.state   = TaskState.FAILED
                result.error   = str(e)
                result.elapsed = time.time() - t0
                log(f"    ✗ {tool} exception: {e}", Colors.YELLOW)
                if attempt < retries:
                    time.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF)-1)])

        self._store(tool, result)
        return result

    # ── PARALLEL EXECUTION ────────────────────────────────────────────────────

    def run_parallel(self, tasks: List[Task],
                     max_workers: int = None) -> Dict[str, ToolResult]:
        """
        Execute a list of Tasks in parallel, respecting depends_on ordering.
        Returns dict {task.name: ToolResult}
        """
        max_workers = max_workers or self.max_workers
        results: Dict[str, ToolResult] = {}
        pending = {t.name: t for t in tasks}
        completed: set = set()
        failed_critical: set = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures: Dict[concurrent.futures.Future, Task] = {}

            def submit_ready():
                """Submit all tasks whose dependencies are met."""
                for name, task in list(pending.items()):
                    if name in completed:
                        continue
                    if any(name == f_task.name for f_task in futures.values()):
                        continue  # already running

                    # Skip if critical dependency failed
                    if any(dep in failed_critical for dep in task.depends_on):
                        log(f"    ⊘ Skipping {name} (critical dependency failed)", Colors.DIM)
                        r = ToolResult(tool=name, cmd=task.cmd, state=TaskState.SKIPPED)
                        results[name] = r
                        completed.add(name)
                        del pending[name]
                        continue

                    # Check all dependencies done
                    if all(dep in completed for dep in task.depends_on):
                        log(f"    ▶ Starting: {name}", Colors.DIM)
                        fut = pool.submit(
                            self.run, task.name, task.cmd,
                            timeout=task.timeout,
                            retries=task.retries,
                            env=task.env,
                            cwd=task.cwd,
                            live=task.live,
                        )
                        futures[fut] = task
                        del pending[name]

            # Initial submit
            submit_ready()

            while futures:
                done, _ = concurrent.futures.wait(
                    futures, timeout=1.0,
                    return_when=concurrent.futures.FIRST_COMPLETED)

                for fut in done:
                    task = futures.pop(fut)
                    try:
                        result = fut.result()
                    except Exception as e:
                        result = ToolResult(tool=task.name, cmd=task.cmd,
                                            state=TaskState.FAILED, error=str(e))

                    results[task.name] = result
                    completed.add(task.name)

                    elapsed_str = f"{result.elapsed:.1f}s" if result.elapsed else "?"
                    if result.success:
                        log(f"    ✓ {task.name} complete ({elapsed_str})", Colors.GREEN)
                        if task.on_success:
                            try: task.on_success(result)
                            except Exception: pass
                    else:
                        log(f"    ✗ {task.name} {result.state.name} ({elapsed_str})", Colors.YELLOW)
                        if task.critical:
                            failed_critical.add(task.name)
                        if task.on_failure:
                            try: task.on_failure(result)
                            except Exception: pass

                # Submit newly unblocked tasks
                submit_ready()

                if self._cancelled.is_set():
                    for fut in futures:
                        fut.cancel()
                    break

        return results

    # ── PARALLEL RECON SHORTCUT ───────────────────────────────────────────────

    def run_recon_parallel(self, target: str, config: dict) -> Dict[str, ToolResult]:
        """
        Run nmap + sublist3r + amass + theHarvester simultaneously.
        Returns results keyed by tool name.
        """
        import shutil
        ports = config.get("ports", "21,22,80,443,445,3306,3389,8080,8443")

        tasks = []

        if shutil.which("nmap"):
            tasks.append(Task(
                name="nmap",
                cmd=["nmap", "-sT", "-sV", "--open", "-T4", "-p", ports,
                     "--host-timeout", "120s", target],
                timeout=600, retries=1,
            ))

        if shutil.which("masscan"):
            tasks.append(Task(
                name="masscan",
                cmd=["masscan", target, "-p0-65535", "--rate=5000", "-oJ", "-"],
                timeout=180, retries=0,
            ))

        if shutil.which("sublist3r"):
            import tempfile
            out = tempfile.mktemp(suffix=".txt")
            tasks.append(Task(
                name="sublist3r",
                cmd=["sublist3r", "-d", target, "-o", out, "-n"],
                timeout=180, retries=1,
            ))

        if shutil.which("amass"):
            tasks.append(Task(
                name="amass",
                cmd=["amass", "enum", "-passive", "-d", target],
                timeout=300, retries=0,
            ))

        if shutil.which("theHarvester"):
            tasks.append(Task(
                name="theHarvester",
                cmd=["theHarvester", "-d", target,
                     "-b", "bing,certspotter,crtsh,hackertarget"],
                timeout=120, retries=1,
            ))

        if shutil.which("dnsrecon"):
            tasks.append(Task(
                name="dnsrecon",
                cmd=["dnsrecon", "-d", target, "-t", "std,axfr"],
                timeout=120, retries=1,
            ))

        if not tasks:
            log("  ⚠ No recon tools available — run: sudo apt install nmap dnsrecon amass", Colors.YELLOW)
            return {}

        log(f"  ⚡ Parallel recon: {len(tasks)} tools running simultaneously...", Colors.BOLD_CYAN)
        return self.run_parallel(tasks, max_workers=len(tasks))

    # ── PRIVATE ───────────────────────────────────────────────────────────────

    def _execute(self, tool: str, cmd: list, timeout: int,
                 env: dict, cwd: str, live: bool,
                 result: ToolResult) -> ToolResult:
        """Core subprocess execution."""
        combined_env = os.environ.copy()
        if env:
            combined_env.update(env)

        if self.verbose:
            log(f"    $ {' '.join(str(c) for c in cmd)}", Colors.DIM)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=combined_env,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )

        stdout_parts = []
        stderr_parts = []

        if live:
            # Stream stdout in real-time
            output_queue = queue.Queue()

            def reader(stream, dest):
                for line in iter(stream.readline, ""):
                    dest.append(line)
                    if live:
                        output_queue.put(line.rstrip())
                stream.close()

            t_out = threading.Thread(target=reader, args=(proc.stdout, stdout_parts), daemon=True)
            t_err = threading.Thread(target=reader, args=(proc.stderr, stderr_parts), daemon=True)
            t_out.start(); t_err.start()

            deadline = time.time() + timeout
            while proc.poll() is None:
                if time.time() > deadline:
                    self._kill(proc)
                    result.state = TaskState.TIMEOUT
                    return result
                try:
                    line = output_queue.get(timeout=0.5)
                    if self.verbose:
                        print(f"      {Colors.DIM}{line}{Colors.RESET}")
                except queue.Empty:
                    pass

            t_out.join(2); t_err.join(2)
        else:
            try:
                stdout_raw, stderr_raw = proc.communicate(timeout=timeout)
                stdout_parts.append(stdout_raw)
                stderr_parts.append(stderr_raw)
            except subprocess.TimeoutExpired:
                self._kill(proc)
                proc.communicate()
                result.state = TaskState.TIMEOUT
                return result

        result.returncode = proc.returncode
        result.stdout     = "".join(stdout_parts)
        result.stderr     = "".join(stderr_parts)
        result.state      = TaskState.SUCCESS if proc.returncode == 0 else TaskState.FAILED

        # Some tools return non-zero but still produced useful output
        if result.returncode != 0 and result.stdout:
            result.state = TaskState.SUCCESS  # treat as success if stdout exists

        return result

    def _kill(self, proc):
        """Kill process group."""
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _store(self, tool: str, result: ToolResult):
        with self._lock:
            self._results[tool] = result

    def cancel_all(self):
        """Signal all running tasks to stop."""
        self._cancelled.set()
        log("  Executor: cancellation requested", Colors.YELLOW)

    @property
    def all_results(self) -> Dict[str, ToolResult]:
        with self._lock:
            return dict(self._results)
