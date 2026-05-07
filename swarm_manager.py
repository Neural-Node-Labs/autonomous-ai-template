#!/usr/bin/env python3
"""
# =============================================================================
# swarm_manager.py
# =============================================================================
# Project  : OMNIKON SEC·OPS — AI Swarm Manager
# Version  : v1.0.2
# Language : Python 3.11+
# License  : MIT
#
# Production-grade agent swarm pool with priority task queue, per-agent
# isolated memory, retry/back-off, health monitoring, and result aggregation.
#
# Architecture:
#   SwarmManager              — top-level orchestrator, consumer API
#     ├── AgentPool           — fixed or elastic set of AgentWorker slots
#     │     └── AgentWorker   — wraps Agent + MemoryManager, runs in thread
#     ├── PriorityTaskQueue   — CRITICAL > HIGH > NORMAL > LOW
#     └── HealthMonitor       — heartbeat, stuck-task detection, auto-restart
#
# Consumer API:
#   with SwarmManager(pool_size=10) as swarm:
#       results = swarm.run_tasks([
#           Task(objective="Analyse log",   skills=["log_analyzer"]),
#           Task(objective="Search CVE-X",  skills=["web_search"]),
#       ])
# =============================================================================
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# Resolve imports relative to repo root
_REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "agent" / "python"))

from memory_manager import MemoryManager, TraceType  # noqa: E402
from agent import Agent, ReactEngine, call_deepseek   # noqa: E402

logger = logging.getLogger("SwarmManager")

# ─────────────────────────────────────────────────────────────────────────────
# Enums & domain models
# ─────────────────────────────────────────────────────────────────────────────

class Priority(int, Enum):
    CRITICAL = 0
    HIGH     = 1
    NORMAL   = 2
    LOW      = 3


class TaskStatus(str, Enum):
    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    DONE      = "DONE"
    FAILED    = "FAILED"
    CANCELLED = "CANCELLED"


class WorkerState(str, Enum):
    IDLE     = "IDLE"
    BUSY     = "BUSY"
    DRAINING = "DRAINING"
    DEAD     = "DEAD"


@dataclass(order=True)
class Task:
    """Unit of work dispatched to a swarm agent."""
    priority:    int       = field(default=Priority.NORMAL)
    # non-comparable fields
    id:          str       = field(default_factory=lambda: str(uuid.uuid4()), compare=False)
    objective:   str       = field(default="",    compare=False)
    skills:      list[str] = field(default_factory=list, compare=False)
    use_react:   bool      = field(default=True,  compare=False)
    context:     str       = field(default="",    compare=False)
    timeout_s:   float     = field(default=120.0, compare=False)
    max_retries: int       = field(default=2,     compare=False)
    metadata:    dict      = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.objective.strip():
            raise ValueError("Task.objective must not be empty")


@dataclass
class TaskResult:
    """Outcome of a single Task execution."""
    task_id:     str
    agent_id:    str
    status:      TaskStatus
    output:      str   = ""
    error:       str   = ""
    attempts:    int   = 0
    latency_ms:  int   = 0
    started_at:  float = field(default_factory=time.time)
    finished_at: float = 0.0
    metadata:    dict  = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id":     self.task_id,
            "agent_id":    self.agent_id,
            "status":      self.status.value,
            "output":      self.output[:2000],
            "error":       self.error,
            "attempts":    self.attempts,
            "latency_ms":  self.latency_ms,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
        }


# ─────────────────────────────────────────────────────────────────────────────
# AgentWorker
# ─────────────────────────────────────────────────────────────────────────────

class AgentWorker:
    """
    A single pooled agent with its own isolated MemoryManager.
    Runs tasks synchronously inside an executor thread.
    """

    def __init__(self, worker_id: str, archive_dir: Path) -> None:
        self.id            = worker_id
        self.state         = WorkerState.IDLE
        self.current_task: Task | None = None
        self._lock         = threading.RLock()
        self._last_beat    = time.time()
        self._tasks_done   = 0
        self._tasks_failed = 0

        archive_path = archive_dir / f"{worker_id}.jsonl"
        self._agent  = Agent(archive_path=str(archive_path))
        logger.info("AgentWorker %s ready", worker_id)

    # ── public ────────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        with self._lock:
            return self.state == WorkerState.IDLE

    def execute(self, task: Task) -> TaskResult:
        with self._lock:
            self.state        = WorkerState.BUSY
            self.current_task = task

        result = TaskResult(task_id=task.id, agent_id=self.id,
                            status=TaskStatus.RUNNING, started_at=time.time())
        logger.info("[%s] → task %s: %r", self.id, task.id, task.objective[:70])

        try:
            self._beat()
            output = self._run(task)
            result.output    = output
            result.status    = TaskStatus.DONE
            self._tasks_done += 1
        except Exception as exc:
            result.error      = str(exc)
            result.status     = TaskStatus.FAILED
            self._tasks_failed += 1
            logger.error("[%s] task %s failed: %s", self.id, task.id, exc, exc_info=True)
        finally:
            result.finished_at = time.time()
            result.latency_ms  = int((result.finished_at - result.started_at) * 1000)
            with self._lock:
                self.state        = WorkerState.IDLE
                self.current_task = None

        return result

    def drain(self)     -> None:
        with self._lock: self.state = WorkerState.DRAINING

    def mark_dead(self) -> None:
        with self._lock: self.state = WorkerState.DEAD

    def heartbeat_age_s(self) -> float:
        return time.time() - self._last_beat

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id":           self.id,
                "state":        self.state.value,
                "tasks_done":   self._tasks_done,
                "tasks_failed": self._tasks_failed,
                "current_task": self.current_task.id if self.current_task else None,
                "beat_age_s":   round(self.heartbeat_age_s(), 1),
            }

    # ── private ───────────────────────────────────────────────────────────────

    def _beat(self) -> None:
        self._last_beat = time.time()

    def _run(self, task: Task) -> str:
        mm = self._agent.mm
        if task.context.strip():
            mm.add_task_content(task.context)
        if task.use_react:
            engine = ReactEngine(mm, self._agent.skills)
            return engine.run(task.objective)
        mm.add_user_message(task.objective)
        system   = mm.context_for_query(task.objective, top_k=3)
        messages = mm.working.build_messages()
        reply    = call_deepseek(system, messages)
        mm.add_assistant_message(reply)
        return reply


# ─────────────────────────────────────────────────────────────────────────────
# AgentPool
# ─────────────────────────────────────────────────────────────────────────────

class AgentPool:
    """Thread-safe pool of AgentWorker instances."""

    def __init__(self, pool_size: int, archive_dir: Path,
                 elastic: bool = False, max_size: int = 50) -> None:
        self._workers: dict[str, AgentWorker] = {}
        self._lock        = threading.RLock()
        self._archive_dir = archive_dir
        self._elastic     = elastic
        self._max_size    = max_size
        archive_dir.mkdir(parents=True, exist_ok=True)
        self._grow(pool_size)

    def _new_worker(self) -> AgentWorker:
        wid = f"agent-{uuid.uuid4().hex[:8]}"
        return AgentWorker(wid, self._archive_dir)

    def _grow(self, n: int) -> None:
        with self._lock:
            for _ in range(n):
                if len(self._workers) >= self._max_size:
                    break
                w = self._new_worker()
                self._workers[w.id] = w

    def acquire(self) -> AgentWorker | None:
        with self._lock:
            for w in self._workers.values():
                if w.is_available():
                    return w
            if self._elastic and len(self._workers) < self._max_size:
                w = self._new_worker()
                self._workers[w.id] = w
                logger.info("AgentPool: elastic scale-up → %d workers", len(self._workers))
                return w
        return None

    def remove(self, wid: str) -> None:
        with self._lock: self._workers.pop(wid, None)

    def replace(self, wid: str) -> AgentWorker:
        self.remove(wid)
        with self._lock:
            w = self._new_worker()
            self._workers[w.id] = w
        logger.info("AgentPool: replaced %s → %s", wid, w.id)
        return w

    def size(self)       -> int: return len(self._workers)
    def idle_count(self) -> int:
        with self._lock:
            return sum(1 for w in self._workers.values() if w.is_available())

    def all_stats(self)  -> list[dict[str, Any]]:
        with self._lock: return [w.stats() for w in self._workers.values()]

    def drain_all(self)  -> None:
        with self._lock:
            for w in self._workers.values(): w.drain()

    def get(self, wid: str) -> AgentWorker | None:
        with self._lock: return self._workers.get(wid)


# ─────────────────────────────────────────────────────────────────────────────
# SwarmManager
# ─────────────────────────────────────────────────────────────────────────────

class SwarmManager:
    """
    Top-level swarm orchestrator.

    Quick start
    -----------
    with SwarmManager(pool_size=10) as swarm:
        results = swarm.run_tasks([
            Task(objective="Analyse logs for brute-force", use_react=True),
            Task(objective="Summarise CVE-2024-1234",     use_react=False),
        ])
    """

    _DISPATCH_SLEEP_S = 0.05
    _HEALTH_SLEEP_S   = 10.0
    _STUCK_S          = 180.0

    def __init__(
        self,
        pool_size:   int              = 5,
        archive_dir: str | Path | None = None,
        elastic:     bool             = False,
        max_size:    int              = 50,
    ) -> None:
        self._archive_dir = Path(archive_dir) if archive_dir else \
                            Path(tempfile.mkdtemp(prefix="swarm_archives_"))
        self._pool     = AgentPool(pool_size, self._archive_dir, elastic, max_size)
        self._q: queue.PriorityQueue[tuple[int, float, Task]] = queue.PriorityQueue()
        self._futures: dict[str, Future[TaskResult]] = {}
        self._results: dict[str, TaskResult]         = {}
        self._lock     = threading.RLock()
        self._running  = False
        self._executor = ThreadPoolExecutor(
            max_workers=max(pool_size * 2, 32),
            thread_name_prefix="swarm",
        )
        self._total_submitted = 0
        self._total_done      = 0
        self._total_failed    = 0
        self._started_at      = time.time()

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> "SwarmManager":
        self._running = True
        threading.Thread(target=self._dispatch_loop, daemon=True, name="swarm-dispatch").start()
        threading.Thread(target=self._health_loop,   daemon=True, name="swarm-health").start()
        logger.info("SwarmManager started: %d workers | archive=%s",
                    self._pool.size(), self._archive_dir)
        return self

    def shutdown(self, wait: bool = True, timeout_s: float = 60.0) -> None:
        logger.info("SwarmManager: shutdown (wait=%s)...", wait)
        self._pool.drain_all()
        self._running = False
        if wait:
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                with self._lock:
                    pending = [f for f in self._futures.values() if not f.done()]
                if not pending:
                    break
                time.sleep(0.3)
        self._executor.shutdown(wait=wait)
        logger.info("SwarmManager: shutdown complete.")

    def __enter__(self)        -> "SwarmManager": return self.start()
    def __exit__(self, *_: Any) -> None:           self.shutdown(wait=True)

    # ── task API ──────────────────────────────────────────────────────────────

    def submit(self, task: Task) -> "Future[TaskResult]":
        """Submit one task. Non-blocking. Returns a Future."""
        future: Future[TaskResult] = Future()
        with self._lock:
            self._futures[task.id] = future
            self._total_submitted += 1
        self._q.put((task.priority, time.time(), task))
        logger.debug("Submitted %s (priority=%s)", task.id, Priority(task.priority).name)
        return future

    def run_tasks(self, tasks: list[Task], timeout_s: float = 300.0) -> list[TaskResult]:
        """Submit all tasks; block until all done or timeout. Returns ordered results."""
        futures  = {t.id: self.submit(t) for t in tasks}
        results: list[TaskResult] = []
        deadline = time.time() + timeout_s
        for t in tasks:
            remaining = max(0.0, deadline - time.time())
            try:
                results.append(futures[t.id].result(timeout=remaining))
            except Exception as exc:
                results.append(TaskResult(
                    task_id=t.id, agent_id="none",
                    status=TaskStatus.FAILED, error=str(exc),
                ))
        return results

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            f = self._futures.get(task_id)
            if f and not f.done():
                f.set_result(TaskResult(task_id=task_id, agent_id="none",
                                        status=TaskStatus.CANCELLED))
                return True
        return False

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            in_flight = sum(1 for f in self._futures.values() if not f.done())
        return {
            "version":         "v1.0.2",
            "pool_size":       self._pool.size(),
            "pool_idle":       self._pool.idle_count(),
            "queue_depth":     self._q.qsize(),
            "in_flight":       in_flight,
            "total_submitted": self._total_submitted,
            "total_done":      self._total_done,
            "total_failed":    self._total_failed,
            "uptime_s":        round(time.time() - self._started_at, 1),
            "workers":         self._pool.all_stats(),
        }

    def result(self, task_id: str) -> TaskResult | None:
        with self._lock: return self._results.get(task_id)

    # ── internal ──────────────────────────────────────────────────────────────

    def _dispatch_loop(self) -> None:
        while self._running or not self._q.empty():
            try:
                try:
                    _, _, task = self._q.get(timeout=self._DISPATCH_SLEEP_S)
                except queue.Empty:
                    continue

                with self._lock:
                    f = self._futures.get(task.id)
                if f and f.done():
                    self._q.task_done()
                    continue

                worker = None
                while worker is None and self._running:
                    worker = self._pool.acquire()
                    if worker is None:
                        time.sleep(self._DISPATCH_SLEEP_S)

                if worker:
                    self._executor.submit(self._run_with_retry, worker, task, f)
                self._q.task_done()

            except Exception as exc:
                logger.error("Dispatch error: %s", exc, exc_info=True)

    def _run_with_retry(
        self,
        worker: AgentWorker,
        task:   Task,
        future: "Future[TaskResult]",
    ) -> None:
        result: TaskResult | None = None
        for attempt in range(1, task.max_retries + 2):
            result           = worker.execute(task)
            result.attempts  = attempt
            if result.status == TaskStatus.DONE:
                break
            if attempt <= task.max_retries:
                backoff = min(2 ** (attempt - 1), 30)
                logger.info("[%s] retry task %s in %ds (attempt %d/%d)",
                            worker.id, task.id, backoff, attempt + 1, task.max_retries + 1)
                time.sleep(backoff)

        if result is None:
            result = TaskResult(task_id=task.id, agent_id=worker.id,
                                status=TaskStatus.FAILED, error="no result")

        with self._lock:
            self._results[task.id] = result
            if result.status == TaskStatus.DONE:
                self._total_done += 1
            else:
                self._total_failed += 1

        if not future.done():
            future.set_result(result)

    def _health_loop(self) -> None:
        while self._running:
            time.sleep(self._HEALTH_SLEEP_S)
            for s in self._pool.all_stats():
                if s["state"] == WorkerState.DEAD.value:
                    logger.warning("Worker %s DEAD — replacing", s["id"])
                    self._pool.replace(s["id"])
                elif s["state"] == WorkerState.BUSY.value and s["beat_age_s"] > self._STUCK_S:
                    logger.warning("Worker %s STUCK (%.0fs) — replacing", s["id"], s["beat_age_s"])
                    w = self._pool.get(s["id"])
                    if w: w.mark_dead()
                    self._pool.replace(s["id"])


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json as _json

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)-5s] %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    p = argparse.ArgumentParser(description="OMNIKON Swarm Manager v1.0.2")
    p.add_argument("--pool",     type=int, default=3)
    p.add_argument("--elastic",  action="store_true")
    p.add_argument("--max-size", type=int, default=20)
    p.add_argument("--archive",  default=None)
    p.add_argument("--no-react", action="store_true")
    args = p.parse_args()

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║    OMNIKON SEC·OPS — Swarm Manager  v1.0.2  (Python)    ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    print("  submit <obj>           submit one task")
    print("  batch <o1> | <o2> …   submit multiple tasks")
    print("  metrics                pool metrics")
    print("  quit                   shutdown\n")

    use_react = not args.no_react

    with SwarmManager(pool_size=args.pool, archive_dir=args.archive,
                      elastic=args.elastic, max_size=args.max_size) as swarm:
        print(f"  Pool: {swarm._pool.size()} agents | archive: {swarm._archive_dir}\n")
        while True:
            try:
                line = input("Swarm > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line: continue
            cmd, _, rest = line.partition(" ")
            cmd = cmd.lower()
            if cmd in ("quit", "exit"):
                break
            elif cmd == "metrics":
                print(_json.dumps(swarm.metrics(), indent=2, default=str))
            elif cmd == "submit":
                if not rest.strip(): print("Usage: submit <objective>"); continue
                t = Task(objective=rest.strip(), use_react=use_react)
                f = swarm.submit(t)
                print(f"Task {t.id} submitted...")
                try:
                    r = f.result(timeout=120)
                    print(f"\n[{r.status.value}] {r.latency_ms}ms\n{r.output}\n")
                except Exception as e:
                    print(f"Error: {e}")
            elif cmd == "batch":
                objs = [o.strip() for o in rest.split("|") if o.strip()]
                if not objs: print("Usage: batch <o1> | <o2>"); continue
                tasks   = [Task(objective=o, use_react=use_react) for o in objs]
                print(f"Submitting {len(tasks)} tasks...")
                results = swarm.run_tasks(tasks, timeout_s=300)
                for r in results:
                    print(f"  [{r.status.value}] {r.task_id} ({r.latency_ms}ms): {r.output[:100]}")
            else:
                print(f"Unknown: {cmd}")

    print("\nGoodbye.")
