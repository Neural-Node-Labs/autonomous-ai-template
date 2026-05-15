# OMNIKON SEC·OPS — AI Memory System

> **Version: v1.0.2** | Production-grade polyglot AI agent framework with ReAct, Swarm orchestration, and 22 real SecOps skills.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Feature Matrix](#feature-matrix)
3. [22 SecOps Skills](#22-secops-skills)
4. [Python](#python)
5. [TypeScript](#typescript)
6. [Java](#java)
7. [Rust](#rust)
8. [SecOps Dashboard UI](#secops-dashboard-ui)
9. [Quickstart by Language](#quickstart-by-language)
10. [Environment Variables](#environment-variables)
11. [ReAct Guide](#react-guide)
12. [Swarm Guide](#swarm-guide)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  SecOpsDashboard.jsx  (React UI — browser)                       │
│  Dispatches swarm jobs, visualises results, 22 skill presets     │
└──────────────────────────────┬───────────────────────────────────┘
                               │  HTTP / direct
┌──────────────────────────────▼───────────────────────────────────┐
│  SwarmManager                                                    │
│  Priority Queue (CRITICAL > HIGH > NORMAL > LOW)                 │
│  ├── AgentWorker × N  (isolated MemoryManager per agent)         │
│  └── Health monitor · elastic pool · auto-retry                  │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│  Agent  (ReAct execution engine + 22 SecOps Skills)              │
│  Thought → Action → Observation → … → Final Answer              │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│  MemoryManager  (5 layers)                                       │
│  2.1 System  · 2.2 Task  · 2.3 Status  · 2.4 Character          │
│  2.5 Reasoning  ← ReAct trace (active only during ReAct)         │
└──────────────────────────────┬───────────────────────────────────┘
                               │  summarise → persist
┌──────────────────────────────▼───────────────────────────────────┐
│  Archive  (Append-only JSONL · thread-safe · cosine retrieval)   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Feature Matrix

| Feature | Python | TypeScript | Java | Rust |
|---------|:------:|:----------:|:----:|:----:|
| MemoryManager layers 2.1–2.5 | ✅ | ✅ | ✅ | ✅ |
| ReasoningMemory (layer 2.5) | ✅ | ✅ | ✅ | ✅ |
| ReAct engine (Thought→Action→Observation) | ✅ | ✅ | ✅ | ✅ |
| 22 SecOps Skills | ✅ | ✅ | ✅ | ✅ |
| SwarmManager | ✅ | ✅ | ✅ | ✅ |
| Priority task queue | ✅ | ✅ | ✅ | ✅ |
| DeepSeek LLM | ✅ | ✅ | ✅ | ✅ |
| JSONL archive (atomic writes) | ✅ | ✅ | ✅ | ✅ |
| Thread/async-safe | ✅ | ✅ | ✅ | ✅ |
| Zero external runtime deps | ✅ | ✅ | ✅ | ✅ |

---

## 22 SecOps Skills

All skills produce real output — no mocks. Every skill is implemented identically across all 4 languages.

| Category | Skill | Description |
|----------|-------|-------------|
| **NETWORK** | `port_scanner` | TCP connect scan, banner grab, up to 500 ports |
| | `dns_lookup` | A/AAAA/MX/TXT/NS/CNAME/PTR via system resolver + dig |
| | `whois_lookup` | Real WHOIS via TCP port 43 with IANA referral follow |
| | `ssl_cert_inspector` | TLS cert expiry, issuer, SANs, cipher, protocol |
| | `http_header_analyzer` | HSTS/CSP/X-Frame/XCTO/Referrer-Policy audit |
| | `network_recon` | CIDR host discovery, service sweep, topology |
| | `dns_security` | DNSSEC, zone transfer attempt, SPF/DKIM/DMARC |
| **THREAT** | `cve_lookup` | NVD/NIST public API — no key required |
| | `ip_reputation` | AbuseIPDB + 3 DNSBL checks |
| | `hash_lookup` | MD5/SHA1/SHA256 + VirusTotal (optional key) |
| | `ioc_extractor` | Extract IPs, domains, hashes, CVEs, emails, URLs |
| **ANALYSIS** | `log_analyzer` | Brute-force, SQLi, XSS, path traversal detection |
| | `vulnerability_scorer` | CVSS v3.1 + OWASP risk rating via AI |
| | `vulnerability_assessment` | Port scan → service fingerprint → NVD correlation |
| | `web_app_scanner` | OWASP Top 10 active: SQLi probe, XSS probe, paths |
| | `api_security_audit` | Auth check, CORS, rate-limit, endpoint discovery |
| | `firewall_auditor` | iptables/nftables parse, over-permissive detection |
| **CLOUD** | `cloud_posture` | AWS CLI + S3 public bucket probe |
| | `container_scanner` | Docker inspect, Dockerfile audit, secret scan |
| **AUTH** | `password_audit` | Hash detection, lockout probe, policy check |
| **UTILITY** | `summarizer` | Text summarisation via DeepSeek |
| | `memory_writer` | Persist facts to long-term archive |

Optional API keys for enhanced skill output:
```bash
export ABUSEIPDB_API_KEY=<key>    # ip_reputation — live scoring
export VIRUSTOTAL_API_KEY=<key>   # hash_lookup — malware detection
```

---

## Python

### Files
```
memory_manager.py                        ← Core library (layers 2.1–2.5 + Archive)
agent/python/agent.py                    ← Agent (22 skills + ReAct + DeepSeek)
swarm/python/swarm_manager.py            ← Swarm orchestrator
```

### Requirements
- Python 3.11+
- Zero runtime dependencies (stdlib only)

### Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
export DEEPSEEK_API_KEY=sk-...
```

### Run Agent
```bash
python agent/python/agent.py
python agent/python/agent.py --archive /data/memory.jsonl

LOG_LEVEL=DEBUG python agent/python/agent.py
```

### Run Swarm
```bash
python swarm/python/swarm_manager.py
# Interactive CLI: /spawn 5  /run example.com port_scanner ssl_cert_inspector
# /react "Full security audit of example.com"
# /health  /results  /quit
```

### Library Usage
```python
from memory_manager import MemoryManager, TraceType

mm = MemoryManager("archive.jsonl")
mm.character.name = "My Agent"
mm.add_system_rule("Always cite evidence.")

# Task
mm.start_task("Audit example.com", steps=["recon","scan","report"])
mm.add_user_message("Start the audit")
prompt = mm.context_for_query("audit", top_k=3)
messages = mm.working.build_messages()

# ReAct
mm.enable_react("Full audit of example.com")
mm.react.record(TraceType.THOUGHT, "I'll start with DNS lookup")
mm.react.record(TraceType.ACTION, "dns_lookup example.com", tool_name="dns_lookup")
mm.react.record(TraceType.OBSERVATION, "A: 93.184.216.34")
mm.finish_react("Audit complete.")
```

### Self-test
```bash
python memory_manager.py --test    # 19/19 tests
```

---

## TypeScript

### Files
```
typescript/src/memoryManager.ts          ← Core library (layers 2.1–2.5 + Archive)
agent/typescript/src/agent.ts            ← Agent (22 skills + ReAct + DeepSeek)
swarm/typescript/src/swarmManager.ts     ← Swarm orchestrator
typescript/package.json
typescript/tsconfig.json
```

### Requirements
- Node.js 18+
- Zero runtime dependencies

### Setup
```bash
cd typescript
npm install           # installs typescript + ts-node (dev only)
export DEEPSEEK_API_KEY=sk-...
```

### Run Agent
```bash
# Development (no compile)
npm run dev
# or
npx ts-node src/agent.ts

# Production build
npm run build && npm start
```

### Run Swarm
```bash
npx ts-node swarm/typescript/src/swarmManager.ts

# Commands: /spawn 5  /run example.com port_scanner ssl_cert_inspector
#           /react "Full security audit"  /health  /results  /quit
```

### Library Usage
```typescript
import { MemoryManager } from "./memoryManager.js";

const mm = await MemoryManager.create("archive.jsonl");
mm.character.name = "My Agent";
mm.addSystemRule("Always cite evidence.");

// Task
mm.startTask("Audit example.com", ["recon","scan","report"]);
mm.addUserMessage("Start the audit");
const prompt   = mm.contextForQuery("audit", 3);
const messages = mm.working.buildMessages();

// ReAct
mm.enableReact("Full audit of example.com");
mm.react.record("THOUGHT", "I'll start with DNS lookup");
mm.react.record("ACTION",  "dns_lookup example.com", "dns_lookup");
mm.react.record("OBSERVATION", "A: 93.184.216.34");
await mm.finishReact("Audit complete.");
```

### package.json scripts
```json
{
  "scripts": {
    "dev":       "ts-node src/agent.ts",
    "build":     "tsc",
    "start":     "node dist/agent.js",
    "typecheck": "tsc --noEmit"
  }
}
```

---

## Java

### Files
```
java/src/main/java/memory/MemoryManager.java   ← Core library (layers 2.1–2.5)
agent/java/src/main/java/agent/Agent.java      ← Agent (22 skills + ReAct + DeepSeek)
swarm/java/src/main/java/swarm/SwarmManager.java ← Swarm orchestrator
java/pom.xml                                   ← Maven build
```

### Requirements
- Java 17+ (uses records, sealed interfaces, HttpClient)
- Maven 3.8+ (optional — can use javac directly)
- Zero runtime dependencies

### Setup
```bash
export DEEPSEEK_API_KEY=sk-...
```

### Build and Run Agent (Maven)
```bash
cd java
mvn package -q
java -jar target/omnikon-agent.jar

# Custom archive
ARCHIVE_PATH=/data/memory.jsonl java -jar target/omnikon-agent.jar
```

### Build and Run Agent (javac — no Maven)
```bash
mkdir -p out
javac -d out \
  java/src/main/java/memory/MemoryManager.java \
  agent/java/src/main/java/agent/Agent.java

java -cp out agent.Agent
```

### Build and Run Swarm
```bash
javac -d out \
  java/src/main/java/memory/MemoryManager.java \
  swarm/java/src/main/java/swarm/SwarmManager.java

java -cp out swarm.SwarmManager

# Commands: spawn 5  run example.com port_scanner  react "Full audit"
#           health   results   quit
```

### Library Usage
```java
import memory.*;
import java.nio.file.Path;
import java.util.List;

MemoryManager mm = new MemoryManager(Path.of("archive.jsonl"));
mm.character().name = "My Agent";
mm.addSystemRule("Always cite evidence.");

// Task
mm.startTask("Audit example.com", List.of("recon","scan","report"));
mm.addUserMessage("Start the audit");
String prompt = mm.contextForQuery("audit", 3, 0.05);
var messages  = mm.working.buildMessages();

// ReAct
mm.enableReact("Full audit of example.com");
mm.react().record(TraceType.THOUGHT, "I'll start with DNS lookup");
mm.react().record(TraceType.ACTION,  "dns_lookup example.com", "dns_lookup", false, 0);
mm.react().record(TraceType.OBSERVATION, "A: 93.184.216.34");
mm.finishReact("Audit complete.");
```

### Logging (JUL)
Create `logging.properties`:
```properties
handlers=java.util.logging.ConsoleHandler
.level=INFO
java.util.logging.ConsoleHandler.level=ALL
java.util.logging.SimpleFormatter.format=%1$tT [%4$-5s] %3$s | %5$s%n

# Verbose ReAct:
memory.ReasoningMemory.level=FINE
```
```bash
java -Djava.util.logging.config.file=logging.properties -jar target/omnikon-agent.jar
```

---

## Rust

### Files
```
rust/src/memory_manager.rs               ← Core library (layers 2.1–2.5 + Archive)
rust/src/agent.rs                        ← Agent (22 skills + ReAct + DeepSeek)
rust/Cargo.toml                          ← Agent binary config
swarm/rust/src/swarm_manager.rs          ← Swarm orchestrator
swarm/rust/Cargo.toml                    ← Swarm binary config
```

### Requirements
- Rust 1.75+
- Runtime crates: `serde`, `serde_json`, `uuid`, `regex`, `log`, `env_logger`, `ureq`, `parking_lot`, `md5`, `sha2`

### Setup
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
export DEEPSEEK_API_KEY=sk-...
```

### Build and Run Agent
```bash
cd rust
cargo build --release
./target/release/agent

# Custom archive
cargo run --release -- --archive /data/memory.jsonl

# Debug logging
RUST_LOG=debug cargo run --release
```

### Build and Run Swarm
```bash
cd swarm/rust
cargo build --release
./target/release/swarm

# Commands: spawn 5  run example.com port_scanner  react "Full audit"
#           health   results   skills   quit
```

### Library Usage
```rust
use memory_manager::{MemoryManager, TraceType};

let mm = MemoryManager::new("archive.jsonl");

mm.working.with_character_mut(|c| {
    c.name = "My Agent".to_string();
    c.tone = "analytical".to_string();
});
mm.add_system_rule("Always cite evidence.");

// Task
mm.start_task("Audit example.com", vec!["recon".into(), "scan".into()]);
mm.add_user_message("Start the audit");
let prompt   = mm.context_for_query("audit", 3, 0.05);
let messages = mm.working.build_messages();

// ReAct
mm.enable_react("Full audit of example.com");
mm.working.reasoning().record(TraceType::Thought, "I'll start with DNS lookup", "", false, 0);
mm.working.reasoning().record(TraceType::Action, "dns_lookup example.com", "dns_lookup", false, 0);
mm.working.reasoning().record(TraceType::Observation, "A: 93.184.216.34", "", false, 0);
mm.finish_react("Audit complete.");
```

### Test suite
```bash
cd rust && cargo test
```

### Logging
```bash
RUST_LOG=info  cargo run --release   # default
RUST_LOG=debug cargo run --release   # verbose ReAct steps
RUST_LOG=memory_manager=debug,agent=info cargo run --release
```

---

## SecOps Dashboard UI

### File
```
ui/src/SecOpsDashboard.jsx               ← React dashboard (runs in browser)
```

### Features
- **Target management** — multi-target input, one per line
- **Language selector** — Python / TypeScript / Java / Rust backends
- **Agent count slider** — 1–20 agents per language
- **ReAct mode toggle** — autonomous Thought→Action loop
- **8 scan presets** — Full Recon, Vuln Scan, Web Audit, Cloud Posture, Threat Hunt, DNS Deep, Auth Audit, Full Pentest
- **22 skill chips** — per-category, multi-select
- **Live console** — real-time scan log with severity colouring
- **Result cards** — expandable, coloured by severity, terminal output
- **Swarm panel** — pool health, architecture diagram, metrics
- **Scan history** — last 20 runs with critical count

### Run (standalone React)
```bash
# Option 1: Vite
npm create vite@latest secops-ui -- --template react
cp ui/src/SecOpsDashboard.jsx secops-ui/src/App.jsx
cd secops-ui && npm install && npm run dev

# Option 2: In existing React project
# Copy SecOpsDashboard.jsx and import as default export
```

### Connect to Real Backends
Replace the `callSwarm()` function in the JSX with real HTTP calls:
```javascript
async function callSwarm({ targets, skills, agentCount, lang }) {
  const response = await fetch(`${lang.api}/swarm/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targets, skills, agent_count: agentCount }),
  });
  return response.json();
}
```

Backend API endpoints (implement in each language's swarm manager):
```
POST /swarm/run      { targets[], skills[], agent_count }  → TaskResult[]
GET  /swarm/health   → SwarmHealth
GET  /swarm/skills   → string[]
```

---

## Quickstart by Language

```bash
export DEEPSEEK_API_KEY=sk-...

# ── Python ─────────────────────────────────────────────────────────
python agent/python/agent.py

# ── TypeScript ─────────────────────────────────────────────────────
cd typescript && npm install && npx ts-node src/agent.ts

# ── Java ───────────────────────────────────────────────────────────
cd java && mvn package -q && java -jar target/omnikon-agent.jar

# ── Rust ───────────────────────────────────────────────────────────
cd rust && cargo run --release

# ── Swarm (any language) ───────────────────────────────────────────
python swarm/python/swarm_manager.py                         # Python
npx ts-node swarm/typescript/src/swarmManager.ts             # TypeScript
java -cp out swarm.SwarmManager                              # Java
cd swarm/rust && cargo run --release                         # Rust

# ── UI Dashboard ───────────────────────────────────────────────────
# Copy ui/src/SecOpsDashboard.jsx into a React project and run
```

---

## Environment Variables

| Variable | Required | Used by | Description |
|----------|:--------:|---------|-------------|
| `DEEPSEEK_API_KEY` | ✅ | All agents & swarms | DeepSeek API key from platform.deepseek.com |
| `ARCHIVE_PATH` | ❌ | All agents | Custom JSONL archive path (default: `agent_memory.jsonl`) |
| `ABUSEIPDB_API_KEY` | ❌ | `ip_reputation` | Live IP reputation scoring |
| `VIRUSTOTAL_API_KEY` | ❌ | `hash_lookup` | Live file/hash malware detection |
| `LOG_LEVEL` | ❌ | Python | `DEBUG/INFO/WARNING/ERROR` |
| `RUST_LOG` | ❌ | Rust | `debug/info/warn/error` or per-module |

---

## Agent Commands

All 4 language agents share the same command vocabulary:

| Command | Description |
|---------|-------------|
| `/skills` | List all 22 SecOps skills with usage |
| `/skill <name> <args>` | Run a skill directly |
| `/react <goal>` | Autonomous ReAct loop (max 10 iterations) |
| `/react-step [goal]` | Run one ReAct iteration interactively |
| `/react-status` | Show live trace + loop metrics (layer 2.5) |
| `/react-finish [ans]` | Close loop, archive trace, disable layer 2.5 |
| `/task <obj> [\ step1 \ …]` | Start a tracked task |
| `/step [label]` | Complete next pending step |
| `/finish [summary]` | Archive task and clear working memory |
| `/status` | Memory snapshot (all 5 layers) |
| `/archive <text>` | Store fact to long-term memory |
| `/recall <query>` | Semantic search of archive |
| `/quit` | Graceful shutdown |

---

## Swarm Commands

| Command | Description |
|---------|-------------|
| `spawn <n>` / `/spawn <n>` | Provision n additional agents |
| `run <target> <skill…>` | Dispatch skill task to pool |
| `react <goal>` | Dispatch full ReAct task |
| `health` | Pool health — idle/busy/queue/done/failed |
| `results` | Show latest batch results |
| `skills` | List all 22 skills |
| `quit` | Graceful shutdown |

---

## ReAct Guide

```
You > /react Full security audit of example.com

🔄 ReAct: Full security audit of example.com
────────────────────────────────────────────────────────────
  💭 [1] I should start with DNS resolution to understand the target.
  ⚡ [1] Action: dns_lookup example.com
  👁 [1] A records: 93.184.216.34
  💭 [2] Now I'll scan for open ports on 93.184.216.34.
  ⚡ [2] Action: port_scanner example.com 80,443,8080,8443
  👁 [2]   80/tcp  OPEN  http
           443/tcp OPEN  https
  💭 [3] Port 443 is open. Let me inspect the SSL certificate.
  ⚡ [3] Action: ssl_cert_inspector example.com
  👁 [3] Expiry: 2025-11-15 — 180d left [valid]
  💭 [4] I have enough to produce the final report.
  ✅ Final: ## Security Audit — example.com
            [LOW] All findings within normal parameters...
────────────────────────────────────────────────────────────
```

### Layer 2.5 — ReasoningMemory
- Activated **only** during `/react` sessions — zero overhead otherwise
- Every Thought/Action/Observation/Final step recorded with latency metrics
- Full trace injected into every system prompt — LLM never repeats failed actions
- Auto-archived to long-term memory on `finish_react`

---

## Swarm Guide

```
Swarm > spawn 5
✓ Pool size now: 9

Swarm > run example.com port_scanner dns_lookup ssl_cert_inspector
Dispatching task a3f2c1d4 …
SwarmResult[a3f2c1d4] 1/1 done, 0 failed, 0 cancelled, 4.2s

  Task a3f2c1d4 (example.com) → DONE | 4.2s | Skills: port_scanner, dns_lookup, ssl_cert_inspector

Swarm > react "Find all open attack surface on example.com"
Starting ReAct task b8e9f012 …
[ReAct loop runs autonomously with all 22 skills available]

Swarm > health
Pool: 9  Idle: 8  Busy: 1  Queue: 0  Done: 2  Failed: 0
  [Idle    ] a3f2c1d4  done=1 failed=0
  [Busy    ] b8e9f012  done=0 failed=0  current=react_task
  ...
```

---

## LLM Swap Guide

All agents use DeepSeek by default (OpenAI-compatible endpoint).
To switch provider, change the API URL and model string in each agent file:

| Provider | Base URL | Model |
|----------|----------|-------|
| **DeepSeek** (default) | `https://api.deepseek.com/v1/chat/completions` | `deepseek-chat` |
| OpenAI | `https://api.openai.com/v1/chat/completions` | `gpt-4o` |
| Anthropic | `https://api.anthropic.com/v1/messages` | `claude-sonnet-4-5` |
| Groq | `https://api.groq.com/openai/v1/chat/completions` | `llama-3.1-70b-versatile` |
| Ollama (local) | `http://localhost:11434/v1/chat/completions` | `llama3.2` |

---

## Production Checklist

### All Languages
- [x] Thread/async-safe archive writes (RLock / promise queue / RwLock / Mutex)
- [x] Atomic temp-file swap on archive rewrite
- [x] Corrupt JSONL line resilience — skip + warn, no crash
- [x] UTF-8-safe truncation — no split multi-byte sequences
- [x] Auto-summarisation loop (condenses old turns into archive)
- [x] Stop-word filtered bag-of-words cosine retrieval

### Skills
- [x] 22 skills implemented identically across Python / TypeScript / Java / Rust
- [x] No mocks — all skills make real network/system calls
- [x] Optional API keys (AbuseIPDB, VirusTotal) — graceful fallback without them
- [x] Skill results archived to long-term memory when `store_to_archive=true`

### ReAct
- [x] Max 10 iteration guard
- [x] Max 3 consecutive error guard
- [x] Layer 2.5 (ReasoningMemory) active only during ReAct — zero overhead otherwise
- [x] Full trace auto-archived on `finish_react`
- [x] LLM sees execution history — avoids repeating failed actions

### Swarm
- [x] Priority queue (CRITICAL > HIGH > NORMAL > LOW)
- [x] Per-agent isolated MemoryManager + archive
- [x] Elastic pool (grow on demand up to max)
- [x] Timeout handling — pending tasks marked cancelled
- [x] Health monitoring — idle/busy/queue/done/failed counts
