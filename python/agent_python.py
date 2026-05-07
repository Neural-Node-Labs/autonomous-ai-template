#!/usr/bin/env python3
"""
agent.py  v3  — ReAct edition
==============================
OMNIKON SEC·OPS AI Memory Agent (Python)

New in v3
---------
- Full ReAct (Reason + Act) execution engine:
    Thought → Action → Observation → … → Final Answer
- ReasoningMemory (layer 2.5) activated automatically per ReAct session;
  the LLM sees its own step history + loop metrics in every system prompt
- /react <goal>         autonomous loop (up to MAX_ITERATIONS)
- /react-step <goal>    run one iteration interactively
- /react-status         live trace + health metrics
- /react-finish         force-close + archive the trace
- DeepSeek deepseek-chat as LLM (OpenAI-compatible, stdlib-only)
- 6 built-in skills usable both directly and inside ReAct loops

Usage
-----
    export DEEPSEEK_API_KEY=sk-...
    python agent.py [--archive PATH]
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from memory_manager import MemoryManager, TraceType

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)-5s] %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Agent")

# ─────────────────────────────────────────────────────────────────────────────
# DeepSeek API  (stdlib-only)
# ─────────────────────────────────────────────────────────────────────────────

DEEPSEEK_URL   = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"
MAX_TOKENS     = 4096


def _api_key() -> str:
    k = os.getenv("DEEPSEEK_API_KEY", "")
    if not k:
        raise RuntimeError(
            "DEEPSEEK_API_KEY not set.\n"
            "  export DEEPSEEK_API_KEY=sk-...")
    return k


def call_deepseek(system: str, messages: list[dict], *,
                  max_tokens: int = MAX_TOKENS, temperature: float = 0.7) -> str:
    payload = json.dumps({
        "model": DEEPSEEK_MODEL, "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "system", "content": system}] + messages,
    }).encode()
    req = urllib.request.Request(
        DEEPSEEK_URL, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {_api_key()}"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"DeepSeek {e.code}: {e.read().decode()!r}") from e


# ─────────────────────────────────────────────────────────────────────────────
# Skill system
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SkillResult:
    skill: str; success: bool; output: str
    store_to_archive: bool = False
    archive_tags: list[str] = field(default_factory=list)


class Skill(ABC):
    trigger_patterns: list[str] = []
    @property
    @abstractmethod
    def name(self) -> str: ...
    @property
    @abstractmethod
    def description(self) -> str: ...
    @property
    @abstractmethod
    def usage(self) -> str: ...
    @abstractmethod
    def run(self, args: str, mm: MemoryManager) -> SkillResult: ...


class WebSearchSkill(Skill):
    name = "web_search"; description = "Search the web (stub — wire to SerpAPI/Brave)"
    usage = "web_search <query>"; trigger_patterns = ["search for","look up","find information about"]
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        return SkillResult(self.name, True,
            f"[web_search] '{args}'\nStub — endpoint: https://serpapi.com/search?q={urllib.request.quote(args)}&api_key=KEY",
            True, ["web_search"])


class CodeExecutorSkill(Skill):
    name = "code_executor"; description = "Execute Python snippet (10s timeout)"
    usage = "code_executor <python code>"; trigger_patterns = ["run code","execute","calculate"]
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        try:
            p = subprocess.run([sys.executable, "-c", args], capture_output=True, text=True, timeout=10)
            out = p.stdout.strip() or p.stderr.strip() or "(no output)"
            return SkillResult(self.name, p.returncode == 0,
                               f"{'✓' if p.returncode==0 else f'✗ exit {p.returncode}'}\n```\n{out}\n```")
        except subprocess.TimeoutExpired:
            return SkillResult(self.name, False, "⚠ Timed out after 10s")
        except Exception as e:
            return SkillResult(self.name, False, f"⚠ {e}")


class LogAnalyzerSkill(Skill):
    name = "log_analyzer"; description = "Parse logs — extract IPs, timestamps, anomalies"
    usage = "log_analyzer <log text>"; trigger_patterns = ["analyze log","parse log","check logs"]
    _IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?")
    _ERR = re.compile(r"\b(ERROR|CRITICAL|FATAL|FAILED_LOGIN|EXCEPTION|WARN)\b", re.I)
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        lines = args.splitlines()
        ips = sorted(set(self._IP.findall(args))); ts = sorted(set(self._TS.findall(args)))
        brute: dict[str, int] = {}
        for l in lines:
            if "FAILED_LOGIN" in l.upper():
                for ip in self._IP.findall(l): brute[ip] = brute.get(ip,0)+1
        findings = []
        if ips: findings.append(f"IPs: {', '.join(ips)}")
        if ts:  findings.append(f"Timestamps: {ts[0]} … {ts[-1]}")
        for ip, n in brute.items():
            findings.append(f"{'[CRITICAL]' if n>=5 else '[WARN]'} {n} failed logins from {ip}")
        out = "**Log Analysis**\n" + "\n".join(findings) if findings else "No anomalies."
        return SkillResult(self.name, True, out, True, ["log_analysis"]+["brute-force"]*bool(brute))


class ThreatLookupSkill(Skill):
    name = "threat_lookup"; description = "Look up IOC against archive threat database"
    usage = "threat_lookup <indicator>"; trigger_patterns = ["threat intel","check cve","lookup indicator"]
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        hits = mm.archive.retrieve(args.strip(), top_k=3, min_score=0.05)
        if not hits: return SkillResult(self.name, True, f"No intel for: `{args}`")
        return SkillResult(self.name, True,
            f"**Intel for `{args}`:**\n" + "\n".join(f"- [{h.source}] {h.content[:200]}" for h in hits))


class SummarizerSkill(Skill):
    name = "summarizer"; description = "Summarize text using DeepSeek"
    usage = "summarizer <text>"; trigger_patterns = ["summarize","tldr","condense"]
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        try:
            s = call_deepseek("Return only a concise summary, no preamble.",
                              [{"role":"user","content":f"Summarize:\n{args[:6000]}"}],
                              max_tokens=512, temperature=0.3)
            return SkillResult(self.name, True, f"**Summary:**\n{s}", True, ["summary"])
        except Exception as e:
            return SkillResult(self.name, False, f"⚠ {e}")


class MemoryWriterSkill(Skill):
    name = "memory_writer"; description = "Write a fact to long-term memory"
    usage = "memory_writer <text>"; trigger_patterns = ["remember this","save to memory","note this"]
    def run(self, args, mm):
        if not args.strip(): return SkillResult(self.name, False, f"Usage: {self.usage}")
        e = mm.archive.store(args.strip(), source="skill_memory_writer", tags=["fact"])
        return SkillResult(self.name, True, f"✓ Stored → `{e.id}`")


class SkillRegistry:
    def __init__(self):
        self._s: dict[str, Skill] = {}
    def register(self, s: Skill): self._s[s.name] = s
    def get(self, n: str) -> Skill | None: return self._s.get(n)
    def all(self) -> list[Skill]: return list(self._s.values())
    def detect(self, text: str) -> Skill | None:
        low = text.lower()
        for s in self._s.values():
            for p in s.trigger_patterns:
                if p in low: return s
        return None
    def help_text(self) -> str:
        return "**Skills:**\n" + "\n".join(
            f"  `{s.name}` — {s.description}\n  ReAct: Action: {s.usage}"
            for s in self._s.values())


def _registry() -> SkillRegistry:
    r = SkillRegistry()
    for cls in [WebSearchSkill, CodeExecutorSkill, LogAnalyzerSkill,
                ThreatLookupSkill, SummarizerSkill, MemoryWriterSkill]:
        r.register(cls())
    return r


# ─────────────────────────────────────────────────────────────────────────────
# ReAct Engine
# ─────────────────────────────────────────────────────────────────────────────

_REACT_SYSTEM = """\
You are operating in ReAct (Reason + Act) mode.

Each response MUST follow ONE of these formats:

  Thought: <your reasoning>
  Action: <skill_name> <args>

  — OR —

  Thought: <final reasoning>
  Final Answer: <complete answer>

Available skills:
{skills}

Rules:
- ONE Thought + ONE Action OR ONE Thought + Final Answer per turn.
- Never fabricate Observations — wait for the real result.
- Check layer 2.5 (Reasoning Trace) in context to avoid repeating failed actions.
- Keep Thoughts to 1–3 sentences.
"""

_RE_THOUGHT = re.compile(r"Thought:\s*(.+?)(?=\nAction:|\nFinal Answer:|$)", re.S)
_RE_ACTION  = re.compile(r"Action:\s*(\w+)\s*(.*?)(?:\n|$)", re.S)
_RE_FINAL   = re.compile(r"Final Answer:\s*(.+)", re.S)

MAX_ITER  = 8
MAX_ERRS  = 3


class ReactEngine:
    def __init__(self, mm: MemoryManager, skills: SkillRegistry):
        self.mm = mm; self.skills = skills

    def _sys(self) -> str:
        base = self.mm.context_for_query(self.mm.react.goal, top_k=3)
        react = _REACT_SYSTEM.format(
            skills="\n".join(f"  {s.name}: {s.description}" for s in self.skills.all()))
        return f"{base}\n\n---\n\n{react}"

    def _parse(self, text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        if m := _RE_THOUGHT.search(text): out["thought"] = m.group(1).strip()
        if m := _RE_ACTION.search(text):
            out["action"] = m.group(1).strip(); out["action_args"] = m.group(2).strip()
        if m := _RE_FINAL.search(text):   out["final"] = m.group(1).strip()
        return out

    def _exec_skill(self, name: str, args: str) -> tuple[str, bool]:
        skill = self.skills.get(name)
        if not skill:
            avail = ", ".join(s.name for s in self.skills.all())
            return f"Unknown skill '{name}'. Available: {avail}", True
        try:
            r = skill.run(args, self.mm)
            if r.store_to_archive and r.success:
                self.mm.archive.store(f"[{r.skill}] {r.output[:500]}",
                                      source=f"skill_{r.skill}", tags=r.archive_tags)
            return r.output, not r.success
        except Exception as e:
            return f"Skill error: {e}", True

    def run(self, goal: str) -> str:
        """Full autonomous ReAct loop. Returns final answer."""
        self.mm.enable_react(goal)
        rm = self.mm.react
        errs = 0
        print(f"\n🔄 ReAct: {goal}\n{'─'*60}")

        for i in range(1, MAX_ITER + 1):
            t0  = time.time()
            raw = call_deepseek(self._sys(), self.mm.working.build_messages(), temperature=0.3)
            lat = int((time.time()-t0)*1000)
            p   = self._parse(raw)

            thought = p.get("thought", raw[:200])
            rm.record(TraceType.THOUGHT, thought, latency_ms=lat)
            print(f"  💭 [{i}] {thought[:100]}")

            if "final" in p:
                ans = p["final"]
                rm.record(TraceType.FINAL, ans)
                self.mm.add_assistant_message(ans)
                self.mm.finish_react(ans)
                print(f"  ✅ Final: {ans[:160]}\n{'─'*60}")
                return ans

            act  = p.get("action", "")
            aarg = p.get("action_args", "")

            if not act:
                rm.record(TraceType.OBSERVATION, "No Action in response.", is_error=True)
                self.mm.add_message("user",
                    "No Action found. Please respond with Thought: ... then Action: <skill> <args>")
                errs += 1
            else:
                rm.record(TraceType.ACTION, f"{act} {aarg}", tool_name=act)
                print(f"  ⚡ [{i}] Action: {act} {aarg[:70]}")
                t0 = time.time()
                obs, is_err = self._exec_skill(act, aarg)
                obs_lat = int((time.time()-t0)*1000)
                rm.record(TraceType.OBSERVATION, obs, is_error=is_err, latency_ms=obs_lat)
                print(f"  👁 [{i}] {obs[:100]}")
                if is_err: errs += 1
                self.mm.add_message("user", f"Observation: {obs}")
                self.mm.add_assistant_message(raw)

            if errs >= MAX_ERRS:
                print(f"  ⚠ Max errors reached.")
                break

        fallback = (f"Loop ended after {i} iterations without final answer. "
                    f"Last observation: {rm.last_observation()[:200]}")
        self.mm.finish_react(fallback)
        return fallback

    def step(self, goal: str) -> tuple[str, bool]:
        """One ReAct iteration. Returns (display_text, is_done)."""
        rm = self.mm.react
        if not rm.enabled:
            self.mm.enable_react(goal)
        t0  = time.time()
        raw = call_deepseek(self._sys(), self.mm.working.build_messages(), temperature=0.3)
        lat = int((time.time()-t0)*1000)
        p   = self._parse(raw)
        thought = p.get("thought", raw[:200])
        rm.record(TraceType.THOUGHT, thought, latency_ms=lat)

        if "final" in p:
            ans = p["final"]
            rm.record(TraceType.FINAL, ans)
            self.mm.add_assistant_message(ans)
            self.mm.finish_react(ans)
            return f"✅ **Final Answer:**\n{ans}", True

        act = p.get("action",""); aarg = p.get("action_args","")
        if not act:
            rm.record(TraceType.OBSERVATION, "No Action produced.", is_error=True)
            return f"💭 **Thought:** {thought}\n\n⚠ No Action produced.", False

        rm.record(TraceType.ACTION, f"{act} {aarg}", tool_name=act)
        obs, is_err = self._exec_skill(act, aarg)
        rm.record(TraceType.OBSERVATION, obs, is_error=is_err)
        self.mm.add_message("user", f"Observation: {obs}")
        self.mm.add_assistant_message(raw)
        return (f"💭 **Thought:** {thought}\n\n"
                f"⚡ **Action:** `{act}` {aarg[:80]}\n\n"
                f"👁 **Observation:** {obs[:300]}"), False


# ─────────────────────────────────────────────────────────────────────────────
# Agent
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║       OMNIKON SEC·OPS  —  AI Agent  v3  (Python)            ║
║  LLM    : DeepSeek deepseek-chat                            ║
║  Memory : 2.1 System | 2.2 Task | 2.3 Status |             ║
║           2.4 Character | 2.5 Reasoning (ReAct only)        ║
║─────────────────────────────────────────────────────────────║
║  Memory  : /task /step /finish /status /archive /recall     ║
║  Skills  : /skills  /skill <name> <args>                    ║
║  ReAct   : /react <goal>          full autonomous loop      ║
║            /react-step [goal]     one iteration             ║
║            /react-status          live trace + metrics      ║
║            /react-finish [answer] close + archive           ║
║  General : /quit                                            ║
╚══════════════════════════════════════════════════════════════╝
"""


class Agent:
    def __init__(self, archive_path: str | Path = "agent_memory.jsonl"):
        self.mm     = MemoryManager(archive_path)
        self.skills = _registry()
        self.react  = ReactEngine(self.mm, self.skills)
        self._persona(); self._rules(); self._seed()
        logger.info("Agent v3 ready | %s | %d skills", archive_path, len(self.skills.all()))

    def _persona(self):
        c = self.mm.character
        c.name = "OMNIKON SEC·OPS"; c.tone = "precise and analytical"
        c.expertise = ["cybersecurity","AI systems","threat intelligence","ReAct reasoning"]
        c.personality = "Methodical. Uses ReAct for complex problems. Proactively suggests skills."
        c.response_format = "Markdown"
        c.constraints = [
            "Never reveal API keys or credentials.",
            "Flag every critical finding with [CRITICAL].",
            "In ReAct mode: Thought → Action → Observation format always.",
        ]

    def _rules(self):
        skills = ", ".join(s.name for s in self.skills.all())
        self.mm.add_system_rule("Respond only in English.")
        self.mm.add_system_rule(f"Skills available: {skills}. Suggest: /skill <name> <args>")

    def _seed(self):
        if len(self.mm.archive) > 0: return
        for c, s, t in [
            ("CVE-2024-1234: SQL injection AuthService v2.1. CVSS 9.8. Patch: v2.2+.",
             "knowledge_base", ["cve","sql-injection"]),
            ("Brute-force: 5+ failures single IP <10 min → rate-limit + SOC alert.",
             "playbook", ["brute-force"]),
            ("Incident 2024-03: Public S3 exposed PII. Fix: bucket policies + CloudTrail.",
             "incident_report", ["aws","s3"]),
            ("OWASP Top 10 2021: A01 Broken Access, A02 Crypto Failures, A03 Injection.",
             "knowledge_base", ["owasp"]),
        ]:
            self.mm.archive.store(c, source=s, tags=t)

    def _exec_skill(self, args: str) -> str:
        name, _, sargs = args.strip().partition(" ")
        s = self.skills.get(name.strip())
        if not s: return f"⚠ Unknown skill '{name}'"
        r = s.run(sargs, self.mm)
        if r.store_to_archive and r.success:
            self.mm.archive.store(f"[{r.skill}] {r.output[:500]}",
                                  source=f"skill_{r.skill}", tags=r.archive_tags)
        return r.output

    def chat(self, inp: str) -> str:
        stripped = inp.strip()
        if not stripped: return ""

        if stripped.startswith("/"):
            cmd, _, args = stripped[1:].partition(" ")
            cmd = cmd.lower()
            if cmd in ("quit","exit","q"): raise KeyboardInterrupt
            if cmd == "skills":       return self.skills.help_text()
            if cmd == "skill":        return self._exec_skill(args)
            if cmd == "react":
                if not args.strip(): return "Usage: /react <goal>"
                return self.react.run(args.strip())
            if cmd == "react-step":
                goal = args.strip() or self.mm.react.goal or "Investigate"
                out, done = self.react.step(goal)
                return out + ("\n\n_(done — /react-finish to archive)_" if done
                              else "\n\n_(run /react-step again)_")
            if cmd == "react-status":
                rm = self.mm.react
                if not rm.enabled: return "ℹ ReAct not active."
                d = rm.snapshot_dict()
                lines = ["```",
                         f"Goal: {d['goal']}  Iters: {d['total_iterations']}  "
                         f"Tools: {d['total_tool_calls']}  Errors: {d['total_errors']}  "
                         f"Elapsed: {d['elapsed_s']}s", "```", "**Last 6 steps:**"]
                lines += ["  " + t.short() for t in rm.traces()[-6:]]
                return "\n".join(lines)
            if cmd == "react-finish":
                e = self.mm.finish_react(args.strip())
                return "✓ ReAct closed." + (f" Archived → `{e.id}`" if e else "")
            if cmd == "task":
                parts = args.split("|"); obj = parts[0].strip()
                if not obj: return "Usage: /task <objective> [| step1 | ...]"
                steps = [s.strip() for s in parts[1:] if s.strip()]
                self.mm.start_task(obj, steps or None)
                return f"✓ Task: **{obj}**"
            if cmd == "step":
                try:
                    self.mm.complete_step(args.strip() or None)
                    s = self.mm.status
                    return f"✓ Step {s.current_step}/{s.total_steps} | Next: {', '.join(s.pending) or 'none'}"
                except RuntimeError as e: return f"⚠ {e}"
            if cmd == "finish":
                try:
                    e = self.mm.finish_task(args.strip() or None)
                    return f"✓ Archived → `{e.id}`"
                except RuntimeError as e: return f"⚠ {e}"
            if cmd == "status":
                snap = self.mm.snapshot(); ts = snap["task_status"]
                react_line = ("ON — " + snap["reasoning"]["goal"]
                              if snap.get("react_enabled") and snap.get("reasoning") else "OFF")
                return ("```\n"
                        f"Character : {snap['character_name']}\n"
                        f"LLM       : {DEEPSEEK_MODEL}\n"
                        f"Task      : {ts['objective'] or '(none)'} ({ts['progress_pct']}%)\n"
                        f"Archive   : {snap['archive_total']} entries\n"
                        f"Tokens≈   : {snap['estimated_tokens']}\n"
                        f"ReAct     : {react_line}\n"
                        "```")
            if cmd == "archive":
                if not args.strip(): return "Usage: /archive <text>"
                return f"✓ Stored → `{self.mm.archive.store(args.strip(), 'manual').id}`"
            if cmd == "recall":
                if not args.strip(): return "Usage: /recall <query>"
                hits = self.mm.archive.retrieve(args.strip(), top_k=3)
                if not hits: return "No memories found."
                return "**Recall:**\n" + "\n".join(
                    f"{i+1}. [{h.source}] {h.content[:120]}…" for i, h in enumerate(hits))
            return f"Unknown command: /{cmd}"

        if (hint := self.skills.detect(stripped)):
            self.mm.add_task_content(f"[Skill hint: {hint.name} — try /skill {hint.name} or /react]")
        self.mm.add_user_message(stripped)
        reply = call_deepseek(self.mm.context_for_query(stripped, top_k=3),
                              self.mm.working.build_messages())
        self.mm.add_assistant_message(reply)
        return reply


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--archive", default=os.getenv("ARCHIVE_PATH", "agent_memory.jsonl"))
    args = p.parse_args()
    print(BANNER)
    agent = Agent(args.archive)
    print(f"  Archive: {args.archive} ({len(agent.mm.archive)} entries)\n")
    signal.signal(signal.SIGINT, lambda *_: (print("\nGoodbye."), sys.exit(0)))
    while True:
        try:
            line = input("You > ").strip()
        except EOFError:
            break
        if not line: continue
        try:
            r = agent.chat(line)
            if r: print(f"\nAgent >\n{r}\n")
        except KeyboardInterrupt:
            print("\nGoodbye."); break
        except Exception as e:
            logger.error("%s", e, exc_info=True); print(f"\n⚠ {e}\n")


if __name__ == "__main__":
    main()
