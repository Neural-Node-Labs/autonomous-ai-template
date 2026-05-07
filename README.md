# OMNIKON SEC·OPS — AI Autonomus System

> **Version: v1.0.0** | Python 3.11+ · TypeScript/Node 18+ · Java 17+ · Rust 1.75+

> **Polyglot, production-grade, tiered AI memory management with ReAct execution.**
> Implemented in **Python 3.11+**, **Java 17+**, **TypeScript / Node.js 18+**, and **Rust 1.75+**.
> Zero external runtime dependencies in every language.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Memory Layers](#memory-layers)
3. [ReAct Execution Engine](#react-execution-engine)
4. [Repository Layout](#repository-layout)
5. [Project Setup — Python](#project-setup--python)
6. [Project Setup — TypeScript](#project-setup--typescript)
7. [Project Setup — Java](#project-setup--java)
8. [Environment Variables](#environment-variables)
9. [Agent Commands](#agent-commands)
10. [Skills System](#skills-system)
11. [ReAct Usage Guide](#react-usage-guide)
12. [Extending the Archive](#extending-the-archive)
13. [Production Checklist](#production-checklist)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  WORKING MEMORY  (context window "desk")                        │
│                                                                 │
│  2.1  System Memory    — global hard rules & operational config │
│  2.2  Task Memory      — current task data, docs, snippets      │
│  2.3  Status Memory    — step tracker, objective, progress %    │
│  2.4  Character Memory — persona, tone, expertise (outer lens)  │
│  2.5  Reasoning Memory — ReAct trace + loop health  ← NEW      │
│         • ONLY active when ReAct mode is enabled                │
│         • records Thought / Action / Observation / Final        │
│         • surfaces compact trace into every system prompt       │
│         • zero memory overhead when ReAct is off                │
└──────────────────────────────┬──────────────────────────────────┘
                               │  summarize → archive
┌──────────────────────────────▼──────────────────────────────────┐
│  ARCHIVE  (long-term memory)                                    │
│  Append-only JSONL  ·  thread-safe file locking                 │
│  Atomic temp-file swap on rewrite                               │
│  Bag-of-words cosine retrieval  (swap surface for vector DB)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Memory Layers

| Layer | Name | Always Active | Purpose |
|-------|------|:---:|---------|
| 2.1 | System Memory | ✅ | Hard constraints, safety rules, response format |
| 2.2 | Task Memory | ✅ | Files, snippets, and conversation for the current task |
| 2.3 | Status Memory | ✅ | Multi-step task tracker: objective, done/pending steps |
| 2.4 | Character Memory | ✅ | Persona, tone, expertise, personality — the outermost lens |
| 2.5 | Reasoning Memory | ⚡ ReAct only | ReAct trace, loop metrics, last observation |
| — | Archive | ✅ | Long-term JSONL store, semantic retrieval, auto-summarisation |

### Layer 2.5 — ReasoningMemory

Activated exclusively when a ReAct session starts. Records:

- **TraceEntry** — one step: `THOUGHT | ACTION | OBSERVATION | FINAL`
- **ReActLoopMetrics** — iteration count, tool calls, error count, latency
- **prompt_block()** — compact summary injected into every system prompt so the LLM can see what it already tried

When the session ends (`finish_react` / `finishReact`), the full trace is archived to long-term memory and layer 2.5 goes dark.

---

## ReAct Execution Engine

The agents implement the **Reason + Act** loop pattern:

```
Goal
 │
 ▼
┌──────────────┐
│   THOUGHT    │  ← LLM reasons about current state
└──────┬───────┘
       │
       ▼
┌──────────────┐      ┌─────────────────────┐
│   ACTION     │─────▶│   SKILL EXECUTION   │
└──────┬───────┘      └──────────┬──────────┘
       │                         │
       ▼                         ▼
┌──────────────┐      ┌─────────────────────┐
│ OBSERVATION  │◀─────│   SKILL RESULT      │
└──────┬───────┘      └─────────────────────┘
       │
       ▼
  Done? ──Yes──▶ FINAL ANSWER ──▶ Archive trace ──▶ Disable 2.5
   │
   No
   │
   └──▶ loop (max 8 iterations, max 3 consecutive errors)
```

Every step is recorded in **ReasoningMemory (layer 2.5)** and injected back into the next system prompt so the LLM never repeats a failed action.

---

## Repository Layout

```
memory-system/
│
├── README.md                                    ← this file
│
├── memory_manager.py                            ← Python core library (v3)
│
├── python/                                      (no separate dir — file above is the lib)
│
├── typescript/
│   ├── package.json                             ← npm config
│   ├── tsconfig.json                            ← TypeScript compiler config
│   └── src/
│       └── memoryManager.ts                     ← TypeScript core library (v3)
│
├── java/
│   ├── pom.xml                                  ← Maven build (Java 17, fat JAR)
│   └── src/
│       └── main/
│           └── java/
│               └── memory/
│                   └── MemoryManager.java       ← Java core library (v3)
│
├── rust/
│   ├── Cargo.toml                                   ← Cargo build (Rust 1.75+)
│   └── src/
│       ├── memory_manager.rs                     ← Rust core library (v1.0.0)
│       └── agent.rs                              ← Rust agent (DeepSeek + ReAct + skills)
│
└── agent/
    ├── python/
    │   └── agent.py                             ← Python agent (DeepSeek + ReAct + skills)
    │
    ├── typescript/
    │   └── src/
    │       └── agent.ts                         ← TypeScript agent (DeepSeek + ReAct + skills)
    │
    └── java/
        └── src/
            └── main/
                └── java/
                    ├── rust/
│   ├── Cargo.toml                                   ← Cargo build (Rust 1.75+)
│   └── src/
│       ├── memory_manager.rs                     ← Rust core library (v1.0.0)
│       └── agent.rs                              ← Rust agent (DeepSeek + ReAct + skills)
│
└── agent/
                        └── Agent.java           ← Java agent (DeepSeek + ReAct + skills)
```

---

## Project Setup — Python

### Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| Python | 3.11+ | Uses `match`, walrus operator, `tomllib` |
| pip | any | Only needed if using a venv |

**Zero runtime dependencies** — uses only `fcntl`, `json`, `logging`, `math`,
`os`, `re`, `subprocess`, `tempfile`, `threading`, `time`, `uuid`, `urllib`.

### 1. Clone / copy files

```bash
# Minimum files needed:
#   memory_manager.py
#   agent/python/agent.py
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
```

### 3. Set the API key

```bash
export DEEPSEEK_API_KEY=sk-...     # get one at https://platform.deepseek.com/
```

### 4. Run the agent

```bash
python agent/python/agent.py

# Custom archive path:
python agent/python/agent.py --archive /data/my_memory.jsonl

# Verbose logging:
LOG_LEVEL=DEBUG python agent/python/agent.py
```

### 5. Run the memory library self-tests

```bash
python memory_manager.py --test
# Expected: 19/19 passed
```

### 6. Import the library in your own code

```python
from memory_manager import MemoryManager, TraceType

mm = MemoryManager("my_archive.jsonl")

# Configure persona
mm.character.name = "My Agent"
mm.character.tone = "helpful"

# Start a task
mm.start_task("Research topic X", steps=["search", "summarise", "report"])

# Normal conversation
mm.add_user_message("Tell me about X")
system_prompt = mm.context_for_query("X")
messages      = mm.working.build_messages()
# → pass to your LLM of choice

# ReAct session
mm.enable_react("Find and summarise info on X")
mm.react.record(TraceType.THOUGHT, "I should search for X first")
mm.react.record(TraceType.ACTION,  "web_search X", tool_name="web_search")
mm.react.record(TraceType.OBSERVATION, "Found 5 relevant articles")
mm.finish_react("Summary: ...")
```

### Directory structure for a new Python project

```
my-project/
├── memory_manager.py          ← copy from this repo
├── agent.py                   ← your agent (or copy agent/python/agent.py)
├── archive.jsonl              ← created automatically on first run
└── .venv/                     ← virtual environment
```

---

## Project Setup — TypeScript

### Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| Node.js | 18.0+ | Uses `node:fs/promises`, `node:crypto` |
| npm | 8+ | Comes with Node |
| TypeScript | 5.4+ | dev dependency only |
| ts-node | 10.9+ | dev dependency only |

**Zero runtime dependencies** — only Node.js built-ins.

### 1. Install Node.js 18+

```bash
# macOS (Homebrew)
brew install node@18

# Ubuntu / Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Windows — download from https://nodejs.org/

# Verify
node --version   # must be >= 18.0.0
npm --version
```

### 2. Install dev dependencies

```bash
cd typescript
npm install
# Installs: typescript@^5.4, ts-node@^10.9
# No runtime deps.
```

### 3. Set the API key

```bash
export DEEPSEEK_API_KEY=sk-...
```

### 4. Run in development mode (ts-node, no compile step)

```bash
# From the typescript/ directory:
npm run dev
# Equivalent to: npx ts-node --esm src/agent.ts
```

### 5. Build for production

```bash
npm run build
# Compiles src/ → dist/
# Output: dist/memoryManager.js, dist/agent.js, .d.ts, .js.map

npm start
# Equivalent to: node dist/agent.js
```

### 6. Type-check without emitting

```bash
npm run typecheck
```

### 7. Use the library in your own TypeScript project

```typescript
import { MemoryManager } from "./memoryManager.js";

const mm = await MemoryManager.create("archive.jsonl");

// Configure
mm.character.name = "My Agent";
mm.addSystemRule("Always be concise.");

// Start a task
mm.startTask("Analyse logs", ["load", "parse", "report"]);

// Normal conversation
mm.addUserMessage("Check the logs for anomalies");
const systemPrompt = mm.contextForQuery("anomalies");
const messages     = mm.working.buildMessages();
// → pass to your LLM

// ReAct
mm.enableReact("Find anomalies in logs");
mm.react.record("THOUGHT", "I'll use the log_analyzer skill");
mm.react.record("ACTION",  "log_analyzer <logs>", "log_analyzer");
mm.react.record("OBSERVATION", "Found brute-force from 1.2.3.4");
await mm.finishReact("Brute-force confirmed. Block 1.2.3.4.");
```

### Directory structure for a new TypeScript project

```
my-project/
├── package.json
├── tsconfig.json
├── src/
│   ├── memoryManager.ts    ← copy from this repo
│   └── myAgent.ts          ← your agent
├── dist/                   ← compiled output (gitignored)
├── archive.jsonl           ← created automatically
└── node_modules/           ← gitignored
```

### Recommended `.gitignore`

```
node_modules/
dist/
*.jsonl
.env
```

### Recommended `tsconfig.json` for a new project

```jsonc
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "declaration": true,
    "sourceMap": true
  },
  "include": ["src/**/*.ts"]
}
```

---

## Project Setup — Java

### Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| Java (JDK) | 17+ | Uses records, sealed classes, `HttpClient` |
| Maven | 3.8+ | Optional — can compile with `javac` directly |

**Zero runtime dependencies** — only `java.*`, `java.net.http.*`.

### 1. Install Java 17+

```bash
# macOS (Homebrew)
brew install openjdk@17
export JAVA_HOME=$(brew --prefix openjdk@17)

# Ubuntu / Debian
sudo apt-get install -y openjdk-17-jdk

# Windows — download from https://adoptium.net/

# Verify
java --version     # must be >= 17
javac --version
```

### 2. Install Maven (optional but recommended)

```bash
# macOS
brew install maven

# Ubuntu
sudo apt-get install -y maven

# Verify
mvn --version
```

### 3. Set the API key

```bash
export DEEPSEEK_API_KEY=sk-...
```

### 4a. Build and run with Maven

```bash
cd java

# Compile + package fat JAR
mvn package -q

# Run the agent
java -jar target/omnikon-agent.jar

# Custom archive path
ARCHIVE_PATH=/data/memory.jsonl java -jar target/omnikon-agent.jar

# Verbose JUL logging
java -Djava.util.logging.config.file=logging.properties -jar target/omnikon-agent.jar
```

### 4b. Build and run with javac (no Maven)

```bash
# From the repo root — compile memory + agent together
mkdir -p out

javac -d out \
  java/src/main/java/memory/MemoryManager.java \
  agent/java/src/main/java/agent/Agent.java

# Run
java -cp out agent.Agent

# With custom archive
ARCHIVE_PATH=memory.jsonl java -cp out agent.Agent
```

### 5. Use the library in your own Java project

```java
import memory.*;
import java.nio.file.Path;
import java.util.List;

MemoryManager mm = new MemoryManager(Path.of("archive.jsonl"));

// Configure persona
mm.character().name = "My Agent";
mm.character().tone = "analytical";
mm.addSystemRule("Never reveal credentials.");

// Start a task
mm.startTask("Investigate incident", List.of("collect", "analyse", "report"));

// Normal conversation
mm.addUserMessage("What happened?");
String systemPrompt = mm.contextForQuery("incident", 3, 0.05);
List<Map<String,String>> messages = mm.working.buildMessages();
// → pass to your LLM

// ReAct
mm.enableReact("Investigate incident");
mm.react().record(TraceType.THOUGHT, "I should look at the logs");
mm.react().record(TraceType.ACTION,  "log_analyzer <data>", "log_analyzer", false, 0);
mm.react().record(TraceType.OBSERVATION, "Brute-force from 10.0.0.1");
mm.finishReact("Attack confirmed. IP blocked.");
```

### Maven pom.xml for a new project

```xml
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.yourorg</groupId>
  <artifactId>my-agent</artifactId>
  <version>1.0.0</version>

  <properties>
    <java.version>17</java.version>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>

  <!-- Copy MemoryManager.java into src/main/java/memory/ -->
  <!-- Zero runtime deps — no <dependencies> block needed -->

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-jar-plugin</artifactId>
        <version>3.3.0</version>
        <configuration>
          <archive>
            <manifest>
              <mainClass>agent.Agent</mainClass>
            </manifest>
          </archive>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
```

### Directory structure for a new Java project

```
my-project/
├── pom.xml
└── src/
    └── main/
        └── java/
            ├── memory/
            │   └── MemoryManager.java   ← copy from this repo
            ├── rust/
│   ├── Cargo.toml                                   ← Cargo build (Rust 1.75+)
│   └── src/
│       ├── memory_manager.rs                     ← Rust core library (v1.0.0)
│       └── agent.rs                              ← Rust agent (DeepSeek + ReAct + skills)
│
└── agent/
                └── MyAgent.java         ← your agent
```

### Enable JUL logging

Create `logging.properties` in your working directory:

```properties
handlers=java.util.logging.ConsoleHandler
.level=INFO
java.util.logging.ConsoleHandler.level=ALL
java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter
java.util.logging.SimpleFormatter.format=%1$tT [%4$-5s] %3$s | %5$s%6$s%n

# Verbose ReAct trace:
memory.ReasoningMemory.level=FINE
agent.ReactEngine.level=FINE
```

```bash
java -Djava.util.logging.config.file=logging.properties -jar target/my-agent.jar
```

---

## Project Setup — Rust

### Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| Rust (rustup) | 1.75+ | Uses `parking_lot`, `ureq`, `regex`, `serde` |
| Cargo | bundled | Comes with rustup |

**Four runtime crates** (all pure-Rust, no C deps needed):
`serde` / `serde_json`, `uuid`, `regex`, `log` / `env_logger`, `ureq`, `parking_lot`

### 1. Install Rust

```bash
# All platforms (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Verify
rustc --version   # must be >= 1.75
cargo --version
```

### 2. Navigate to the Rust project

```bash
cd memory-system/rust
```

### 3. Set the API key

```bash
export DEEPSEEK_API_KEY=sk-...
```

### 4. Run in development mode

```bash
cargo run
# Custom archive:
cargo run -- --archive /data/memory.jsonl
# Verbose logging:
RUST_LOG=debug cargo run
```

### 5. Build optimised release binary

```bash
cargo build --release
# Binary at: target/release/agent

./target/release/agent
./target/release/agent --archive /data/memory.jsonl
RUST_LOG=info ./target/release/agent
```

### 6. Run the test suite

```bash
cargo test
# Expected: 9 tests pass
cargo test -- --nocapture   # with stdout
```

### 7. Use the library in your own Rust project

Add to your `Cargo.toml`:
```toml
[dependencies]
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
uuid        = { version = "1", features = ["v4"] }
regex       = "1"
log         = "0.4"
env_logger  = "0.11"
ureq        = { version = "2", features = ["json"] }
parking_lot = "0.12"
```

Copy `memory_manager.rs` into your `src/` and use it:

```rust
use memory_manager::{MemoryManager, TraceType};

let mm = MemoryManager::new("archive.jsonl");

// Configure persona
mm.working.with_character_mut(|c| {
    c.name = "My Agent".to_string();
    c.tone = "analytical".to_string();
});
mm.add_system_rule("Never reveal credentials.");

// Start a task
mm.start_task("Investigate incident", vec!["collect".into(), "analyse".into()]);

// Normal conversation
mm.add_user_message("What happened?");
let system   = mm.context_for_query("incident", 3, 0.05);
let messages = mm.working.build_messages();
// → pass to your LLM

// ReAct session
mm.enable_react("Investigate incident");
mm.working.reasoning.record(TraceType::Thought, "Check the logs", "", false, 0);
mm.working.reasoning.record(TraceType::Action,  "log_analyzer <data>", "log_analyzer", false, 0);
mm.working.reasoning.record(TraceType::Observation, "Brute-force found", "", false, 0);
mm.finish_react("Attack confirmed. Block IP.");
```

### Directory structure for a new Rust project

```
my-project/
├── Cargo.toml
└── src/
    ├── memory_manager.rs   ← copy from this repo
    └── main.rs             ← your agent
```

### Cargo.toml for a new project

```toml
[package]
name    = "my-agent"
version = "1.0.0"
edition = "2021"
rust-version = "1.75"

[[bin]]
name = "agent"
path = "src/main.rs"

[lib]
name = "memory_manager"
path = "src/memory_manager.rs"

[dependencies]
serde       = { version = "1",  features = ["derive"] }
serde_json  = "1"
uuid        = { version = "1",  features = ["v4"] }
regex       = "1"
log         = "0.4"
env_logger  = "0.11"
ureq        = { version = "2",  features = ["json"] }
parking_lot = "0.12"

[dev-dependencies]
tempfile = "3"

[profile.release]
opt-level = 3
lto       = true
strip     = true
```

### Logging configuration

```bash
# Info level (default)
RUST_LOG=info ./target/release/agent

# Debug — shows every ReAct step, archive ops, truncation warnings
RUST_LOG=debug ./target/release/agent

# Per-module granularity
RUST_LOG=memory_manager=debug,agent=info ./target/release/agent
```


---

## Environment Variables

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `DEEPSEEK_API_KEY` | ✅ | — | DeepSeek API key from platform.deepseek.com |
| `ARCHIVE_PATH` | ❌ | `agent_memory.jsonl` | Path to the JSONL archive file |
| `LOG_LEVEL` | ❌ | `INFO` | Python only: `DEBUG / INFO / WARNING / ERROR` |

---

## Agent Commands

All three agents share an identical command vocabulary:

### Memory commands

| Command | Description |
|---------|-------------|
| `/task <objective> \| step1 \| step2` | Start a new task (pipe-delimited steps optional) |
| `/step [label]` | Mark the next pending step complete |
| `/finish [summary]` | Archive the task and clear working memory |
| `/status` | Print full memory snapshot |
| `/archive <text>` | Manually store a fact to long-term archive |
| `/recall <query>` | Semantic search of the archive |

### Skill commands

| Command | Description |
|---------|-------------|
| `/skills` | List all available skills |
| `/skill <name> <args>` | Run a specific skill directly |

### ReAct commands

| Command | Description |
|---------|-------------|
| `/react <goal>` | Run a full autonomous ReAct loop (up to 8 iterations) |
| `/react-step [goal]` | Execute one ReAct iteration interactively |
| `/react-status` | Show live trace + loop metrics from layer 2.5 |
| `/react-finish [answer]` | Force-close the loop and archive the trace |

### General

| Command | Description |
|---------|-------------|
| `/quit` | Graceful shutdown |

---

## Skills System

Six built-in skills, usable both directly (`/skill`) and inside ReAct loops (`Action: skill_name args`):

| Skill | Description | ReAct Action format |
|-------|-------------|---------------------|
| `web_search` | Web lookup stub (wire to SerpAPI/Brave/Tavily) | `Action: web_search <query>` |
| `code_executor` | Run Python/JS/shell snippet (10s timeout) | `Action: code_executor <code>` |
| `log_analyzer` | Extract IPs, timestamps, brute-force patterns | `Action: log_analyzer <log text>` |
| `threat_lookup` | Query archive for IOCs (IP, CVE, hash) | `Action: threat_lookup <indicator>` |
| `summarizer` | Condense long text via DeepSeek | `Action: summarizer <text>` |
| `memory_writer` | Write a fact directly to long-term archive | `Action: memory_writer <text>` |

### Auto-intent detection

The agent scans every user message for skill trigger phrases and injects a hint into task memory when a match is found — no command needed.

### Adding a new skill (Python example)

```python
class MySkill(Skill):
    name             = "my_skill"
    description      = "Does something useful"
    usage            = "my_skill <args>"
    trigger_patterns = ["do the thing", "run my skill"]

    def run(self, args: str, mm: MemoryManager) -> SkillResult:
        result = do_something(args)
        return SkillResult(
            skill=self.name, success=True, output=result,
            store_to_archive=True, archive_tags=["my_skill"]
        )

# Register it:
registry.register(MySkill())
```

---

## ReAct Usage Guide

### Full autonomous loop

```
You > /react Investigate the uploaded log file for security anomalies and produce a report

  🔄 ReAct: Investigate the uploaded log file...
  ─────────────────────────────────────────────────────────
  💭 [1] I should analyse the log file for suspicious patterns.
  ⚡ [1] Action: log_analyzer 2024-06-01 FAILED_LOGIN admin ip=192.168.1.99 x7
  👁 [1] [CRITICAL] 7 failed logins from 192.168.1.99
  💭 [2] I should look up threat intel on this IP.
  ⚡ [2] Action: threat_lookup 192.168.1.99
  👁 [2] [playbook] Brute-force pattern: 5+ failures → rate-limit + SOC alert
  💭 [3] I have enough evidence for the final report.
  ✅ Final: ## Security Report
             [CRITICAL] Brute-force attack from 192.168.1.99
             Evidence: 7 failed logins in <5 min
             Recommendation: Block IP, notify SOC, check for successful logins
  ─────────────────────────────────────────────────────────

Agent > ## Security Report
[CRITICAL] Brute-force attack from 192.168.1.99 ...
```

### Step-by-step interactive mode

```
You > /react-step Investigate login anomalies

Agent >
💭 Thought: I should analyse the logs for failed login patterns.
⚡ Action: `log_analyzer` <paste log here>
👁 Observation: [CRITICAL] 5 failed logins from 10.0.0.1

_(run /react-step again)_

You > /react-step

Agent >
💭 Thought: I found a brute-force pattern. Let me check threat intel.
⚡ Action: `threat_lookup` 10.0.0.1
👁 Observation: No specific intel found for 10.0.0.1

_(run /react-step again)_

You > /react-status
```

### Check live trace

```
You > /react-status

Agent >
```
Goal: Investigate login anomalies  Iters: 2  Tools: 2  Errors: 0  Elapsed: 4.3s
```
**Last 6 steps:**
  [THOUGHT i=1] I should analyse the logs for failed login patterns.
  [ACTION i=2] tool=log_analyzer log_analyzer <log text>
  [OBSERVATION i=3] [CRITICAL] 5 failed logins from 10.0.0.1
  [THOUGHT i=4] I found a brute-force pattern. Let me check threat intel.
  [ACTION i=5] tool=threat_lookup threat_lookup 10.0.0.1
  [OBSERVATION i=6] No specific intel found for 10.0.0.1
```

### Close and archive

```
You > /react-finish Brute-force from 10.0.0.1 detected. Recommend IP block.

Agent > ✓ ReAct closed. Archived → `a3f2c1d4-...`
```

---

## Extending the Archive

The retrieval layer is a **drop-in swap surface** — override one method to use any vector database.

### Python

```python
class PineconeArchive(Archive):
    def __init__(self, path, pinecone_index):
        super().__init__(path)
        self.index = pinecone_index

    def retrieve(self, query, top_k=3, min_score=0.05):
        vector   = embed(query)                 # your embedding function
        results  = self.index.query(vector=vector, top_k=top_k)
        return [self.get(match.id) for match in results.matches
                if match.score >= min_score and self.get(match.id)]
```

### TypeScript

```typescript
class PineconeArchive extends Archive {
  retrieve(query: string, topK = 3, minScore = 0.05): ArchiveEntry[] {
    const vector  = embed(query);               // your embedding function
    const results = this.pinecone.query(vector, topK);
    return results.filter(r => r.score >= minScore).map(r => this.get(r.id)!);
  }
}
```

### Java

```java
public class PineconeArchive extends Archive {
    @Override
    public List<ArchiveEntry> retrieve(String query, int topK, double minScore) {
        float[] vector  = embed(query);         // your embedding function
        var results = pineconeClient.query(vector, topK);
        return results.stream()
            .filter(r -> r.score() >= minScore)
            .map(r -> get(r.id()).orElse(null))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
}
```

---

## Production Checklist

### Reliability

- [x] Thread-safe writes — `RLock` (Python) / `ReentrantRWLock` (Java) / promise queue (TS)
- [x] Atomic file swap on rewrite — `os.replace` / `Files.move ATOMIC_MOVE` / `fs.rename`
- [x] Corrupt JSONL line resilience — skip + warn, no crash on startup
- [x] UTF-8-safe truncation — no split multi-byte code points
- [x] File locking on append — `fcntl.flock` / `FileChannel.lock`

### Memory quality

- [x] Stop-word filtered bag-of-words cosine retrieval
- [x] Auto-summarisation loop — condenses old turns into archive
- [x] Context budget enforcement per layer with warnings
- [x] Role validation on conversation messages
- [x] Deduplication of system rules
- [x] Export / import snapshot for cross-process persistence

### ReAct reliability

- [x] Max iteration guard (8 by default — configurable)
- [x] Max consecutive error guard (3 by default)
- [x] No-action response recovery (re-prompts LLM)
- [x] Every step recorded in ReasoningMemory (layer 2.5)
- [x] LLM sees full trace in next prompt — avoids repeated failures
- [x] Auto-archive trace on `finish_react`
- [x] Layer 2.5 goes dark when ReAct ends — zero overhead

### Operations

- [x] Structured logging throughout (stdlib in all three languages)
- [x] Graceful SIGINT / EOF shutdown in all three agents
- [x] Zero external runtime dependencies
- [x] Single-file agents (easy to deploy)
- [x] `ARCHIVE_PATH` env var for configurable persistence

---

## LLM Swap Guide

The agents use **DeepSeek** (`deepseek-chat`, OpenAI-compatible endpoint).
To switch to another provider, update the API call function in each agent:

| Provider | Base URL | Model string |
|----------|----------|--------------|
| DeepSeek | `https://api.deepseek.com/v1/chat/completions` | `deepseek-chat` |
| OpenAI | `https://api.openai.com/v1/chat/completions` | `gpt-4o` |
| Anthropic | `https://api.anthropic.com/v1/messages` | `claude-sonnet-4-5` |
| Groq | `https://api.groq.com/openai/v1/chat/completions` | `llama-3.1-70b-versatile` |
| Ollama (local) | `http://localhost:11434/v1/chat/completions` | `llama3.2` |

All providers except Anthropic use the OpenAI-compatible format already used by the agents.
For Anthropic, swap the request format to use `system` as a top-level field and `x-api-key` header.
