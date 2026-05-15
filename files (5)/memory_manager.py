"""
# =============================================================================
# memory_manager.py
# =============================================================================
# Project  : OMNIKON SEC·OPS — AI Memory System
# Version  : v1.0.2
# Language : Python 3.11+
# License  : MIT
#
# Production-grade tiered AI Memory Management System.
#
# Layers:
#   2.1 System Memory    — hard rules / config
#   2.2 Task Memory      — current task data
#   2.3 Status Memory    — step / state tracker
#   2.4 Character Memory — persona / voice / lens
#   2.5 Reasoning Memory — ReAct loop history (activated ONLY when ReAct is on)
#   Archive              — Append-only JSONL, thread-safe, cosine retrieval
# =============================================================================
"""

from __future__ import annotations

import fcntl
import json
import logging
import math
import os
import re
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Generator, Iterator

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# File locking
# ──────────────────────────────────────────────────────────────────────────────

@contextmanager
def _file_lock(fh: Any) -> Generator[None, None, None]:
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    except (AttributeError, OSError):
        logger.warning("fcntl unavailable; file locking disabled.")
        yield
    finally:
        try:
            fcntl.flock(fh, fcntl.LOCK_UN)
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Vector helpers
# ──────────────────────────────────────────────────────────────────────────────

_STOPWORDS: frozenset[str] = frozenset({
    "a","an","the","and","or","but","in","on","at","to","for","of","with",
    "by","from","is","was","are","were","be","been","has","have","had","do",
    "does","did","not","this","that","it","its","as","so","if","then","than",
    "can","will","would","could","should","may","might","must","shall","about",
    "into","up","out","also","more","no","i","me","my","we","our","you","your",
})


def _bag_of_words(text: str) -> dict[str, int]:
    bow: dict[str, int] = {}
    for t in re.findall(r"[a-z0-9]{2,}", text.lower()):
        if t not in _STOPWORDS:
            bow[t] = bow.get(t, 0) + 1
    return bow


def _cosine(a: dict[str, int], b: dict[str, int]) -> float:
    if not a or not b:
        return 0.0
    keys = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in keys)
    if not dot:
        return 0.0
    return dot / (math.sqrt(sum(v*v for v in a.values())) *
                  math.sqrt(sum(v*v for v in b.values())))


def _utf8_safe_truncate(text: str, max_bytes: int) -> str:
    enc = text.encode("utf-8")
    return text if len(enc) <= max_bytes else enc[:max_bytes].decode("utf-8", errors="ignore")


def _token_estimate(text: str) -> int:
    return len(text.encode("utf-8")) // 4


# ──────────────────────────────────────────────────────────────────────────────
# 2.5  ReasoningMemory — ReAct trace + loop health monitor
# ──────────────────────────────────────────────────────────────────────────────

class TraceType(Enum):
    """The four canonical ReAct step types."""
    THOUGHT     = "THOUGHT"
    ACTION      = "ACTION"
    OBSERVATION = "OBSERVATION"
    FINAL       = "FINAL"


@dataclass
class TraceEntry:
    """One step in the ReAct execution trace."""
    trace_type:  str
    iteration:   int
    content:     str
    tool_name:   str  = ""
    is_error:    bool = False
    latency_ms:  int  = 0
    timestamp:   float = field(default_factory=time.time)

    def short(self) -> str:
        prefix  = f"[{self.trace_type} i={self.iteration}]"
        snippet = self.content[:120].replace("\n", " ")
        tool    = f" tool={self.tool_name}" if self.tool_name else ""
        err     = " ⚠ERROR" if self.is_error else ""
        return f"{prefix}{tool}{err} {snippet}"


@dataclass
class ReActLoopMetrics:
    """Aggregate counters for one ReAct session."""
    total_iterations: int   = 0
    total_tool_calls: int   = 0
    total_errors:     int   = 0
    total_latency_ms: int   = 0
    started_at:       float = field(default_factory=time.time)
    finished_at:      float = 0.0

    @property
    def elapsed_s(self) -> float:
        end = self.finished_at or time.time()
        return round(end - self.started_at, 2)

    @property
    def avg_iter_ms(self) -> float:
        return round(self.total_latency_ms / self.total_iterations, 1) \
               if self.total_iterations else 0.0


class ReasoningMemory:
    """
    Memory layer 2.5 — activated ONLY when ReAct mode is on.

    Records every Thought / Action / Observation / Final step and
    injects a compact trace summary into every system prompt so the
    LLM always knows what it already tried in the current session.

    When finish() is called the full trace is serialised so the
    MemoryManager can archive it to long-term storage.

    Thread-safe.  Zero overhead when disabled.
    """

    PROMPT_BUDGET:     int = 4_000   # max chars injected into system prompt
    MAX_ACTIVE_TRACES: int = 50      # evict oldest beyond this

    def __init__(self) -> None:
        self._lock     = threading.RLock()
        self._traces:  list[TraceEntry]    = []
        self._metrics: ReActLoopMetrics    = ReActLoopMetrics()
        self._goal:    str                 = ""
        self._enabled: bool                = False

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def enable(self, goal: str = "") -> None:
        """Activate and reset for a fresh ReAct session."""
        with self._lock:
            self._enabled = True
            self._traces.clear()
            self._metrics = ReActLoopMetrics()
            self._goal    = goal.strip()
        logger.info("ReasoningMemory: enabled — goal=%r", self._goal)

    def disable(self) -> None:
        with self._lock:
            self._enabled = False
        logger.info("ReasoningMemory: disabled.")

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    @property
    def goal(self) -> str:
        with self._lock:
            return self._goal

    # ── recording ─────────────────────────────────────────────────────────────

    def record(
        self,
        trace_type: TraceType,
        content:    str,
        tool_name:  str  = "",
        is_error:   bool = False,
        latency_ms: int  = 0,
    ) -> TraceEntry:
        """
        Append one step.  Updates loop metrics.
        Raises RuntimeError if called while disabled.
        """
        if not self._enabled:
            raise RuntimeError("ReasoningMemory.record called while disabled.")
        with self._lock:
            self._metrics.total_iterations += 1
            if trace_type == TraceType.ACTION:
                self._metrics.total_tool_calls += 1
            if is_error:
                self._metrics.total_errors += 1
            self._metrics.total_latency_ms += latency_ms

            entry = TraceEntry(
                trace_type=trace_type.value,
                iteration=self._metrics.total_iterations,
                content=content.strip(),
                tool_name=tool_name,
                is_error=is_error,
                latency_ms=latency_ms,
            )
            self._traces.append(entry)
            if len(self._traces) > self.MAX_ACTIVE_TRACES:
                self._traces = self._traces[-self.MAX_ACTIVE_TRACES:]

        logger.debug("ReAct: %s", entry.short())
        return entry

    def finish(self, final_answer: str = "") -> None:
        """Mark the loop done and record the final answer."""
        with self._lock:
            self._metrics.finished_at = time.time()
        if final_answer:
            self.record(TraceType.FINAL, final_answer)
        m = self._metrics
        logger.info(
            "ReAct done: iters=%d tool_calls=%d errors=%d elapsed=%.2fs",
            m.total_iterations, m.total_tool_calls, m.total_errors, m.elapsed_s,
        )

    # ── prompt injection ──────────────────────────────────────────────────────

    def prompt_block(self) -> str:
        """
        Return the text block injected into the system prompt.
        Empty string when disabled or no traces recorded yet.
        """
        with self._lock:
            if not self._enabled or not self._traces:
                return ""
            m = self._metrics
            lines = [
                "## ReAct Reasoning Trace (layer 2.5)",
                f"Goal      : {self._goal or '(not set)'}",
                f"Iterations: {m.total_iterations} | "
                f"Tool calls: {m.total_tool_calls} | "
                f"Errors: {m.total_errors} | "
                f"Elapsed: {m.elapsed_s}s | "
                f"Avg/iter: {m.avg_iter_ms}ms",
                "",
                "Recent steps (last 10):",
            ]
            for t in self._traces[-10:]:
                lines.append("  " + t.short())
            block = "\n".join(lines)
        return _utf8_safe_truncate(block, self.PROMPT_BUDGET)

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_archive_content(self) -> str:
        """Full trace as a string suitable for archive storage."""
        with self._lock:
            m = self._metrics
            parts = [
                f"[ReAct Trace] goal={self._goal!r}",
                f"iterations={m.total_iterations} tool_calls={m.total_tool_calls} "
                f"errors={m.total_errors} elapsed={m.elapsed_s}s",
                "---",
            ] + [t.short() for t in self._traces]
            return "\n".join(parts)

    # ── accessors ─────────────────────────────────────────────────────────────

    def traces(self) -> list[TraceEntry]:
        with self._lock: return list(self._traces)

    def metrics(self) -> ReActLoopMetrics:
        with self._lock: return self._metrics

    def last_observation(self) -> str:
        with self._lock:
            for t in reversed(self._traces):
                if t.trace_type == TraceType.OBSERVATION.value:
                    return t.content
            return ""

    def snapshot_dict(self) -> dict[str, Any]:
        m = self.metrics()
        return {
            "enabled":          self._enabled,
            "goal":             self._goal,
            "total_iterations": m.total_iterations,
            "total_tool_calls": m.total_tool_calls,
            "total_errors":     m.total_errors,
            "elapsed_s":        m.elapsed_s,
            "avg_iter_ms":      m.avg_iter_ms,
            "trace_count":      len(self._traces),
        }


# ──────────────────────────────────────────────────────────────────────────────
# ArchiveEntry
# ──────────────────────────────────────────────────────────────────────────────

_KNOWN_ENTRY_FIELDS = {"id", "timestamp", "source", "content", "tags"}


@dataclass
class ArchiveEntry:
    id:        str
    timestamp: float
    source:    str
    content:   str
    tags:      list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:      raise ValueError("ArchiveEntry.id must not be empty.")
        if not self.content: raise ValueError("ArchiveEntry.content must not be empty.")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ArchiveEntry":
        return cls(**{k: v for k, v in d.items() if k in _KNOWN_ENTRY_FIELDS})


# ──────────────────────────────────────────────────────────────────────────────
# TaskStatus
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class TaskStatus:
    objective:    str       = ""
    total_steps:  int       = 0
    current_step: int       = 0
    completed:    list[str] = field(default_factory=list)
    pending:      list[str] = field(default_factory=list)
    notes:        str       = ""

    @property
    def is_active(self) -> bool:
        return bool(self.objective)

    @property
    def progress_pct(self) -> float:
        return 0.0 if not self.total_steps else round(
            self.current_step / self.total_steps * 100, 1)

    def summary(self) -> str:
        if not self.is_active:
            return "[STATUS] No active task."
        prog = (f"Step {self.current_step}/{self.total_steps} ({self.progress_pct}%)"
                if self.total_steps else "—")
        lines = [
            f"[STATUS] {prog} | Objective: {self.objective}",
            f"  Done   : {', '.join(self.completed) or 'none'}",
            f"  Pending: {', '.join(self.pending) or 'none'}",
        ]
        if self.notes:
            lines.append(f"  Notes  : {self.notes}")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# CharacterMemory
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CharacterMemory:
    name:            str       = "Assistant"
    tone:            str       = "professional"
    expertise:       list[str] = field(default_factory=list)
    personality:     str       = ""
    response_format: str       = "Markdown"
    constraints:     list[str] = field(default_factory=list)

    def persona_block(self) -> str:
        lines = [
            f"You are {self.name}.",
            f"Tone: {self.tone}.",
            f"Expertise: {', '.join(self.expertise) or 'general'}.",
            f"Always respond in: {self.response_format}.",
        ]
        if self.personality:
            lines.append(f"Personality: {self.personality}")
        for c in self.constraints:
            lines.append(f"CONSTRAINT: {c}")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Archive
# ──────────────────────────────────────────────────────────────────────────────

class Archive:
    """Thread-safe append-only JSONL store with cosine retrieval."""

    def __init__(self, path: str | Path = "memory_archive.jsonl") -> None:
        self.path = Path(path)
        self._entries: list[ArchiveEntry] = []
        self._lock = threading.RLock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        loaded = skipped = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    self._entries.append(ArchiveEntry.from_dict(json.loads(raw)))
                    loaded += 1
                except Exception as exc:
                    logger.warning("Archive: corrupt line %d: %s", lineno, exc)
                    skipped += 1
        logger.info("Archive: loaded %d (%d skipped) from %s", loaded, skipped, self.path)

    def _append_to_disk(self, entry: ArchiveEntry) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            with _file_lock(fh):
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def _rewrite_disk(self) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".jsonl.tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                with _file_lock(fh):
                    for e in self._entries:
                        fh.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except Exception:
            try: os.unlink(tmp)
            except OSError: pass
            raise

    def store(self, content: str, source: str = "manual",
              tags: list[str] | None = None) -> ArchiveEntry:
        if not content or not content.strip():
            raise ValueError("Archive.store: content must not be empty.")
        entry = ArchiveEntry(
            id=str(uuid.uuid4()), timestamp=time.time(),
            source=source, content=content.strip(), tags=list(tags or []),
        )
        with self._lock:
            self._entries.append(entry)
            self._append_to_disk(entry)
        return entry

    def retrieve(self, query: str, top_k: int = 3,
                 min_score: float = 0.05) -> list[ArchiveEntry]:
        if not query.strip():
            return []
        q_vec = _bag_of_words(query)
        with self._lock:
            snapshot = list(self._entries)
        scored = [(e, _cosine(q_vec, _bag_of_words(e.content))) for e in snapshot]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [e for e, s in scored[:top_k] if s >= min_score]

    def delete(self, entry_id: str) -> bool:
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.id != entry_id]
            if len(self._entries) == before:
                return False
            self._rewrite_disk()
        return True

    def get(self, entry_id: str) -> ArchiveEntry | None:
        with self._lock:
            return next((e for e in self._entries if e.id == entry_id), None)

    def all_entries(self) -> list[ArchiveEntry]:
        with self._lock: return list(self._entries)

    def __len__(self) -> int:
        with self._lock: return len(self._entries)

    def __iter__(self) -> Iterator[ArchiveEntry]:
        with self._lock: return iter(list(self._entries))


# ──────────────────────────────────────────────────────────────────────────────
# WorkingMemory  (layers 2.1 – 2.5)
# ──────────────────────────────────────────────────────────────────────────────

class WorkingMemory:
    """
    All five memory layers.  Layer 2.5 (reasoning) is injected into
    the system prompt only when ReasoningMemory.enabled is True.
    """

    _BUDGET: dict[str, int] = {
        "character": 1_500,
        "system":    3_000,
        "status":    1_200,
        "reasoning": 4_000,   # 2.5 — only active during ReAct
        "retrieved": 6_000,
        "task":     12_000,
    }
    SUMMARIZE_THRESHOLD: int = 6_000
    KEEP_TURNS:          int = 4

    def __init__(self) -> None:
        self._lock                      = threading.RLock()
        self._system_rules:              list[str]            = []
        self._task_content:              list[str]            = []
        self._conversation_history:      list[dict[str, str]] = []
        self._status:                    TaskStatus           = TaskStatus()
        self._character:                 CharacterMemory      = CharacterMemory()
        self._retrieved:                 list[ArchiveEntry]   = []
        self._reasoning:                 ReasoningMemory      = ReasoningMemory()

    # ── accessors ─────────────────────────────────────────────────────────────

    @property
    def character(self) -> CharacterMemory:  return self._character
    @property
    def status(self) -> TaskStatus:          return self._status
    @property
    def reasoning(self) -> ReasoningMemory:  return self._reasoning

    @property
    def retrieved_count(self) -> int:
        with self._lock: return len(self._retrieved)

    def system_rules(self) -> list[str]:
        with self._lock: return list(self._system_rules)

    def task_content(self) -> list[str]:
        with self._lock: return list(self._task_content)

    def conversation_history(self) -> list[dict[str, str]]:
        with self._lock: return list(self._conversation_history)

    # ── mutators ──────────────────────────────────────────────────────────────

    def add_system_rule(self, rule: str) -> None:
        r = rule.strip()
        if not r: return
        with self._lock:
            if r not in self._system_rules:
                self._system_rules.append(r)

    def add_task_content(self, content: str) -> None:
        c = content.strip()
        if c:
            with self._lock: self._task_content.append(c)

    def add_message(self, role: str, content: str) -> None:
        if role not in {"user", "assistant", "system"}:
            raise ValueError(f"Invalid role: {role!r}")
        with self._lock:
            self._conversation_history.append({"role": role, "content": content})

    def inject_retrieved(self, entries: list[ArchiveEntry]) -> None:
        with self._lock: self._retrieved = list(entries)

    def clear_task(self) -> None:
        with self._lock:
            self._task_content.clear()
            self._conversation_history.clear()
            self._retrieved.clear()
            self._status = TaskStatus()

    def pop_old_turns(self) -> list[dict[str, str]]:
        with self._lock:
            history = list(self._conversation_history)
            if len(history) <= self.KEEP_TURNS:
                return []
            old = history[:-self.KEEP_TURNS]
            self._conversation_history = history[-self.KEEP_TURNS:]
            return old

    # ── prompt assembly ───────────────────────────────────────────────────────

    @staticmethod
    def _truncate(text: str, max_chars: int, label: str = "") -> str:
        if len(text) <= max_chars:
            return text
        half = max_chars // 2
        logger.warning("WorkingMemory: '%s' truncated %d→%d chars", label, len(text), max_chars)
        return _utf8_safe_truncate(text, half) + "\n…[truncated]…\n" + text[-half:]

    def build_system_prompt(self) -> str:
        with self._lock:
            parts: list[str] = []

            # 2.4 Character (outermost lens)
            parts.append(self._truncate(
                self._character.persona_block(), self._BUDGET["character"], "character"))

            # 2.1 System rules
            if self._system_rules:
                block = "\n".join(f"• {r}" for r in self._system_rules)
                parts.append("## System Rules\n" +
                              self._truncate(block, self._BUDGET["system"], "system"))

            # 2.3 Task status
            if self._status.is_active:
                parts.append(self._truncate(
                    self._status.summary(), self._BUDGET["status"], "status"))

            # 2.5 Reasoning trace (only when ReAct enabled)
            react_block = self._reasoning.prompt_block()
            if react_block:
                parts.append(self._truncate(
                    react_block, self._BUDGET["reasoning"], "reasoning"))

            # Retrieved archive context
            if self._retrieved:
                raw = "\n\n".join(
                    f"[Memory {i+1}] (source: {e.source})\n{e.content}"
                    for i, e in enumerate(self._retrieved))
                parts.append("## Relevant Memory\n" +
                              self._truncate(raw, self._BUDGET["retrieved"], "retrieved"))

            # 2.2 Task content
            if self._task_content:
                raw = "\n\n".join(self._task_content)
                parts.append("## Task Context\n" +
                              self._truncate(raw, self._BUDGET["task"], "task"))

            return "\n\n---\n\n".join(parts)

    def build_messages(self) -> list[dict[str, str]]:
        with self._lock: return list(self._conversation_history)

    def token_estimate(self) -> int:
        with self._lock:
            prompt  = self.build_system_prompt()
            history = " ".join(m["content"] for m in self._conversation_history)
        return _token_estimate(prompt + " " + history)


# ──────────────────────────────────────────────────────────────────────────────
# MemoryManager — unified orchestrator
# ──────────────────────────────────────────────────────────────────────────────

class MemoryManager:
    """
    Unified interface for the full memory stack (2.1–2.5 + Archive).

    ReAct usage pattern
    -------------------
        mm.enable_react("Analyse log for brute-force attacks")
        # inside the loop:
        mm.react.record(TraceType.THOUGHT, "I should scan for FAILED_LOGIN")
        mm.react.record(TraceType.ACTION, "log_analyzer ...", tool_name="log_analyzer")
        mm.react.record(TraceType.OBSERVATION, "5 failures from 1.2.3.4")
        # when done:
        mm.finish_react("Brute-force confirmed from 1.2.3.4 — block recommended.")
    """

    def __init__(self, archive_path: str | Path = "memory_archive.jsonl") -> None:
        self.archive = Archive(archive_path)
        self.working = WorkingMemory()
        logger.info("MemoryManager v3 ready. Archive: %s", archive_path)

    # ── proxies ───────────────────────────────────────────────────────────────

    @property
    def character(self) -> CharacterMemory:  return self.working.character
    @property
    def status(self) -> TaskStatus:          return self.working.status
    @property
    def react(self) -> ReasoningMemory:      return self.working.reasoning

    def add_system_rule(self, rule: str) -> None:      self.working.add_system_rule(rule)
    def add_task_content(self, content: str) -> None:  self.working.add_task_content(content)
    def add_user_message(self, content: str) -> None:  self.working.add_message("user", content)
    def add_assistant_message(self, c: str) -> None:   self.working.add_message("assistant", c)

    # ── task lifecycle ────────────────────────────────────────────────────────

    def start_task(self, objective: str, steps: list[str] | None = None) -> None:
        objective = objective.strip()
        if not objective:
            raise ValueError("start_task: objective must not be empty.")
        self.working.clear_task()
        self.working.status.objective = objective
        if steps:
            clean = [s.strip() for s in steps if s.strip()]
            self.working.status.total_steps = len(clean)
            self.working.status.pending = clean
        logger.info("Task started: %r", objective)

    def complete_step(self, step_description: str | None = None) -> None:
        s = self.working.status
        if not s.is_active:
            raise RuntimeError("complete_step: no active task.")
        label = (step_description or "").strip() or \
                (s.pending[0] if s.pending else f"Step {s.current_step+1}")
        if s.pending: s.pending.pop(0)
        s.completed.append(label)
        s.current_step += 1

    def finish_task(self, summary: str | None = None) -> ArchiveEntry:
        s = self.working.status
        if not s.is_active:
            raise RuntimeError("finish_task: no active task.")
        parts = [f"Task: {s.objective}"]
        if summary: parts.append(f"Summary: {summary.strip()}")
        if s.completed: parts.append("Completed: " + "; ".join(s.completed))
        tc = self.working.task_content()
        if tc: parts.append("Snapshot:\n" + "\n".join(tc[:3]))
        entry = self.archive.store("\n".join(parts), "task_summary",
                                   ["task", s.objective[:40]])
        logger.info("Task archived: id=%s", entry.id)
        self.working.clear_task()
        return entry

    # ── ReAct lifecycle ───────────────────────────────────────────────────────

    def enable_react(self, goal: str = "") -> None:
        """Activate ReasoningMemory (layer 2.5) for a new ReAct session."""
        self.working.reasoning.enable(goal)

    def finish_react(self, final_answer: str = "") -> ArchiveEntry | None:
        """
        Close the ReAct loop:
          1. Record final answer in trace
          2. Archive the full trace to long-term memory
          3. Disable ReasoningMemory (layer 2.5 goes dark)
        Returns the ArchiveEntry or None if trace was empty.
        """
        rm = self.working.reasoning
        if not rm.enabled:
            return None
        rm.finish(final_answer)
        content = rm.to_archive_content()
        entry: ArchiveEntry | None = None
        if content.strip():
            entry = self.archive.store(
                content, source="react_trace",
                tags=["react", "reasoning", rm.goal[:40]])
            logger.info("ReAct trace archived: id=%s", entry.id)
        rm.disable()
        return entry

    # ── context assembly ──────────────────────────────────────────────────────

    def context_for_query(self, query: str, top_k: int = 3,
                          min_score: float = 0.05) -> str:
        if self.working.token_estimate() > self.working.SUMMARIZE_THRESHOLD:
            self._summarize_conversation()
        hits = self.archive.retrieve(query, top_k=top_k, min_score=min_score)
        self.working.inject_retrieved(hits)
        return self.working.build_system_prompt()

    def _summarize_conversation(self) -> None:
        old = self.working.pop_old_turns()
        if not old:
            return
        lines = [f"{m['role'].upper()}: {m['content'][:300]}" for m in old]
        self.archive.store("[Conversation summary]\n" + "\n".join(lines),
                           "conversation", ["summary", "auto"])
        logger.info("Summarised %d turns.", len(old))

    # ── snapshot ──────────────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        s = self.working.status
        base: dict[str, Any] = {
            "character_name":    self.working.character.name,
            "system_rule_count": len(self.working.system_rules()),
            "task_status": {
                "objective":      s.objective,
                "progress_pct":   s.progress_pct,
                "current_step":   s.current_step,
                "total_steps":    s.total_steps,
                "pending_count":  len(s.pending),
                "completed_count":len(s.completed),
            },
            "task_content_count":  len(self.working.task_content()),
            "conversation_turns":  len(self.working.conversation_history()),
            "retrieved_count":     self.working.retrieved_count,
            "archive_total":       len(self.archive),
            "estimated_tokens":    self.working.token_estimate(),
            "react_enabled":       self.working.reasoning.enabled,
        }
        if self.working.reasoning.enabled:
            base["reasoning"] = self.working.reasoning.snapshot_dict()
        return base

    def export_snapshot(self) -> dict[str, Any]:
        c = self.working.character
        return {
            "character": asdict(c),
            "system_rules":         self.working.system_rules(),
            "status":               asdict(self.working.status),
            "task_content":         self.working.task_content(),
            "conversation_history": self.working.conversation_history(),
        }

    def import_snapshot(self, data: dict[str, Any]) -> None:
        c = data.get("character", {})
        for attr in ("name","tone","expertise","personality","response_format","constraints"):
            if attr in c: setattr(self.working.character, attr, c[attr])
        for rule in data.get("system_rules", []):
            self.working.add_system_rule(rule)
        s = data.get("status", {})
        for attr in ("objective","total_steps","current_step","completed","pending","notes"):
            if attr in s: setattr(self.working.status, attr, s[attr])
        for item in data.get("task_content", []): self.working.add_task_content(item)
        for msg in data.get("conversation_history", []):
            if msg.get("content"): self.working.add_message(msg.get("role","user"), msg["content"])

    def __repr__(self) -> str:
        snap = self.snapshot()
        react = "ON" if snap["react_enabled"] else "OFF"
        return (f"<MemoryManager | archive={snap['archive_total']}"
                f" | tokens≈{snap['estimated_tokens']}"
                f" | task={snap['task_status']['objective']!r}"
                f" | react={react}>")
