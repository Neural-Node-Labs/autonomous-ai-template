/**
 * =============================================================================
 * swarmManager.ts
 * =============================================================================
 * Project  : OMNIKON SEC·OPS — AI Swarm Manager
 * Version  : v1.0.2
 * Language : TypeScript / Node.js 18+
 * License  : MIT
 *
 * Production-grade agent swarm pool with priority task queue, per-agent
 * isolated memory, retry/back-off, health monitoring, and result aggregation.
 *
 * Architecture:
 *   SwarmManager              — top-level orchestrator, consumer API
 *     ├── AgentPool           — fixed or elastic set of AgentWorker slots
 *     │     └── AgentWorker   — wraps Agent + MemoryManager
 *     ├── PriorityTaskQueue   — CRITICAL > HIGH > NORMAL > LOW
 *     └── HealthMonitor       — heartbeat, stuck-task detection, auto-restart
 *
 * Consumer API:
 *   const swarm = await SwarmManager.create({ poolSize: 10 });
 *   const results = await swarm.runTasks([
 *     { objective: "Analyse log", useReact: true  },
 *     { objective: "Search CVE",  useReact: false },
 *   ]);
 *   await swarm.shutdown();
 * =============================================================================
 */

import * as crypto  from "node:crypto";
import * as os      from "node:os";
import * as path    from "node:path";
import * as fsp     from "node:fs/promises";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

import { MemoryManager }    from "./memoryManager.js";
import { callDeepSeek, Agent, ReactEngine, ALL_SKILLS } from "./agent.js";

// ─────────────────────────────────────────────────────────────────────────────
// Enums & domain models
// ─────────────────────────────────────────────────────────────────────────────

export enum Priority {
  CRITICAL = 0,
  HIGH     = 1,
  NORMAL   = 2,
  LOW      = 3,
}

export enum TaskStatus {
  PENDING   = "PENDING",
  RUNNING   = "RUNNING",
  DONE      = "DONE",
  FAILED    = "FAILED",
  CANCELLED = "CANCELLED",
}

export enum WorkerState {
  IDLE     = "IDLE",
  BUSY     = "BUSY",
  DRAINING = "DRAINING",
  DEAD     = "DEAD",
}

export interface Task {
  id:          string;
  objective:   string;
  skills?:     string[];
  useReact?:   boolean;
  context?:    string;
  priority?:   Priority;
  timeoutMs?:  number;
  maxRetries?: number;
  metadata?:   Record<string, unknown>;
}

export interface TaskResult {
  taskId:      string;
  agentId:     string;
  status:      TaskStatus;
  output:      string;
  error:       string;
  attempts:    number;
  latencyMs:   number;
  startedAt:   number;
  finishedAt:  number;
  metadata:    Record<string, unknown>;
}

function makeTask(t: Partial<Task> & { objective: string }): Task {
  if (!t.objective?.trim()) throw new Error("Task.objective must not be empty");
  return {
    id:          t.id          ?? crypto.randomUUID(),
    objective:   t.objective.trim(),
    skills:      t.skills      ?? [],
    useReact:    t.useReact    ?? true,
    context:     t.context     ?? "",
    priority:    t.priority    ?? Priority.NORMAL,
    timeoutMs:   t.timeoutMs   ?? 120_000,
    maxRetries:  t.maxRetries  ?? 2,
    metadata:    t.metadata    ?? {},
  };
}

function makeResult(
  taskId: string, agentId: string, status: TaskStatus,
  output = "", error = ""
): TaskResult {
  const now = Date.now();
  return { taskId, agentId, status, output, error,
           attempts: 0, latencyMs: 0, startedAt: now, finishedAt: now, metadata: {} };
}

// ─────────────────────────────────────────────────────────────────────────────
// PriorityQueue — min-heap on (priority, arrivalTime)
// ─────────────────────────────────────────────────────────────────────────────

interface QueueItem { priority: number; arrival: number; task: Task; }

class PriorityQueue {
  private heap: QueueItem[] = [];

  push(item: QueueItem): void {
    this.heap.push(item);
    this.heap.sort((a, b) => a.priority - b.priority || a.arrival - b.arrival);
  }
  pop(): QueueItem | undefined { return this.heap.shift(); }
  get size(): number           { return this.heap.length; }
  get isEmpty(): boolean       { return this.heap.length === 0; }
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentWorker  (runs in the same process, async)
// ─────────────────────────────────────────────────────────────────────────────

class AgentWorker {
  readonly id:   string;
  state:         WorkerState   = WorkerState.IDLE;
  currentTask:   Task | null   = null;
  private agent: Agent;
  private lastBeat = Date.now();
  tasksDone   = 0;
  tasksFailed = 0;

  private constructor(id: string, agent: Agent) {
    this.id    = id;
    this.agent = agent;
  }

  static async create(id: string, archivePath: string): Promise<AgentWorker> {
    const agent = await Agent.create(archivePath);
    const w     = new AgentWorker(id, agent);
    console.error(`[INFO] AgentWorker ${id} ready`);
    return w;
  }

  isAvailable(): boolean { return this.state === WorkerState.IDLE; }

  async execute(task: Task): Promise<TaskResult> {
    this.state       = WorkerState.BUSY;
    this.currentTask = task;
    const startedAt  = Date.now();
    const result     = makeResult(task.id, this.id, TaskStatus.RUNNING);
    result.startedAt = startedAt;

    console.error(`[INFO] [${this.id}] → task ${task.id}: "${task.objective.slice(0,70)}"`);
    this.beat();

    try {
      const output     = await this.runTask(task);
      result.output    = output;
      result.status    = TaskStatus.DONE;
      this.tasksDone++;
    } catch (e) {
      result.error     = (e as Error).message;
      result.status    = TaskStatus.FAILED;
      this.tasksFailed++;
      console.error(`[ERROR] [${this.id}] task ${task.id} failed: ${result.error}`);
    } finally {
      result.finishedAt = Date.now();
      result.latencyMs  = result.finishedAt - startedAt;
      this.state        = WorkerState.IDLE;
      this.currentTask  = null;
    }
    return result;
  }

  drain():    void { this.state = WorkerState.DRAINING; }
  markDead(): void { this.state = WorkerState.DEAD; }
  beatAgeMs(): number { return Date.now() - this.lastBeat; }

  stats() {
    return {
      id:          this.id,
      state:       this.state,
      tasksDone:   this.tasksDone,
      tasksFailed: this.tasksFailed,
      currentTask: this.currentTask?.id ?? null,
      beatAgeMs:   this.beatAgeMs(),
    };
  }

  private beat() { this.lastBeat = Date.now(); }

  private async runTask(task: Task): Promise<string> {
    const mm = this.agent["mm"] as MemoryManager;
    if (task.context?.trim()) mm.addTaskContent(task.context);

    if (task.useReact) {
      const engine = new ReactEngine(mm);
      return engine.run(task.objective);
    }
    mm.addUserMessage(task.objective);
    const system   = mm.contextForQuery(task.objective, 3);
    const messages = mm.working.buildMessages();
    const reply    = await callDeepSeek(system, messages);
    mm.addAssistantMessage(reply);
    return reply;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentPool
// ─────────────────────────────────────────────────────────────────────────────

class AgentPool {
  private workers    = new Map<string, AgentWorker>();
  private archiveDir: string;
  private elastic:    boolean;
  private maxSize:    number;

  private constructor(archiveDir: string, elastic: boolean, maxSize: number) {
    this.archiveDir = archiveDir;
    this.elastic    = elastic;
    this.maxSize    = maxSize;
  }

  static async create(
    poolSize:   number,
    archiveDir: string,
    elastic:    boolean,
    maxSize:    number,
  ): Promise<AgentPool> {
    await fsp.mkdir(archiveDir, { recursive: true });
    const pool = new AgentPool(archiveDir, elastic, maxSize);
    await pool.grow(poolSize);
    return pool;
  }

  private async grow(n: number): Promise<void> {
    const promises: Promise<void>[] = [];
    for (let i = 0; i < n && this.workers.size < this.maxSize; i++) {
      const id      = `agent-${crypto.randomUUID().slice(0,8)}`;
      const archive = path.join(this.archiveDir, `${id}.jsonl`);
      promises.push(AgentWorker.create(id, archive).then(w => { this.workers.set(id, w); }));
    }
    await Promise.all(promises);
  }

  async acquire(): Promise<AgentWorker | null> {
    for (const w of this.workers.values()) {
      if (w.isAvailable()) return w;
    }
    if (this.elastic && this.workers.size < this.maxSize) {
      const id      = `agent-${crypto.randomUUID().slice(0,8)}`;
      const archive = path.join(this.archiveDir, `${id}.jsonl`);
      const w       = await AgentWorker.create(id, archive);
      this.workers.set(id, w);
      console.error(`[INFO] AgentPool: elastic scale-up → ${this.workers.size} workers`);
      return w;
    }
    return null;
  }

  async replace(id: string): Promise<AgentWorker> {
    this.workers.delete(id);
    const newId   = `agent-${crypto.randomUUID().slice(0,8)}`;
    const archive = path.join(this.archiveDir, `${newId}.jsonl`);
    const w       = await AgentWorker.create(newId, archive);
    this.workers.set(newId, w);
    console.error(`[INFO] AgentPool: replaced ${id} → ${newId}`);
    return w;
  }

  get(id: string):    AgentWorker | undefined { return this.workers.get(id); }
  get size():         number                  { return this.workers.size; }
  get idleCount():    number                  { return [...this.workers.values()].filter(w => w.isAvailable()).length; }
  allStats():         ReturnType<AgentWorker["stats"]>[] { return [...this.workers.values()].map(w => w.stats()); }
  drainAll():         void                    { this.workers.forEach(w => w.drain()); }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwarmManager
// ─────────────────────────────────────────────────────────────────────────────

export interface SwarmOptions {
  poolSize?:   number;
  archiveDir?: string;
  elastic?:    boolean;
  maxSize?:    number;
}

export class SwarmManager {
  private pool!:    AgentPool;
  private queue     = new PriorityQueue();
  private futures   = new Map<string, { resolve: (r: TaskResult) => void; reject: (e: Error) => void }>();
  private results   = new Map<string, TaskResult>();
  private running   = false;
  private archiveDir: string;

  private totalSubmitted = 0;
  private totalDone      = 0;
  private totalFailed    = 0;
  private startedAt      = Date.now();

  private DISPATCH_MS = 50;
  private HEALTH_MS   = 10_000;
  private STUCK_MS    = 180_000;

  private constructor(archiveDir: string) {
    this.archiveDir = archiveDir;
  }

  static async create(opts: SwarmOptions = {}): Promise<SwarmManager> {
    const archiveDir = opts.archiveDir ?? path.join(os.tmpdir(), `swarm_${Date.now()}`);
    const sm         = new SwarmManager(archiveDir);
    sm.pool          = await AgentPool.create(
      opts.poolSize ?? 5, archiveDir,
      opts.elastic  ?? false, opts.maxSize ?? 50,
    );
    sm.running = true;
    sm.startDispatcher();
    sm.startHealthMonitor();
    console.error(`[INFO] SwarmManager started: ${sm.pool.size} workers | archive=${archiveDir}`);
    return sm;
  }

  async shutdown(waitMs = 60_000): Promise<void> {
    console.error("[INFO] SwarmManager: shutdown...");
    this.pool.drainAll();
    this.running = false;
    const deadline = Date.now() + waitMs;
    while (Date.now() < deadline && this.futures.size > 0) {
      await new Promise(r => setTimeout(r, 300));
    }
    console.error("[INFO] SwarmManager: shutdown complete.");
  }

  // ── task API ──────────────────────────────────────────────────────────────

  submit(partial: Partial<Task> & { objective: string }): Promise<TaskResult> {
    const task = makeTask(partial);
    this.totalSubmitted++;
    const promise = new Promise<TaskResult>((resolve, reject) => {
      this.futures.set(task.id, { resolve, reject });
    });
    this.queue.push({ priority: task.priority ?? Priority.NORMAL, arrival: Date.now(), task });
    console.error(`[DEBUG] Submitted ${task.id} (${Priority[task.priority ?? Priority.NORMAL]})`);
    return promise;
  }

  async runTasks(
    partials:  Array<Partial<Task> & { objective: string }>,
    timeoutMs: number = 300_000,
  ): Promise<TaskResult[]> {
    const promises = partials.map(p => this.submit(p));
    const deadline = Date.now() + timeoutMs;
    return Promise.all(promises.map(p =>
      Promise.race([
        p,
        new Promise<TaskResult>((_, rej) =>
          setTimeout(() => rej(new Error("Task timeout")), Math.max(0, deadline - Date.now()))
        ),
      ]).catch(e => makeResult("?", "none", TaskStatus.FAILED, "", String(e)))
    ));
  }

  cancel(taskId: string): boolean {
    const f = this.futures.get(taskId);
    if (f) {
      f.resolve(makeResult(taskId, "none", TaskStatus.CANCELLED));
      this.futures.delete(taskId);
      return true;
    }
    return false;
  }

  metrics() {
    return {
      version:        "v1.0.2",
      poolSize:       this.pool.size,
      poolIdle:       this.pool.idleCount,
      queueDepth:     this.queue.size,
      inFlight:       this.futures.size,
      totalSubmitted: this.totalSubmitted,
      totalDone:      this.totalDone,
      totalFailed:    this.totalFailed,
      uptimeSec:      ((Date.now() - this.startedAt) / 1000).toFixed(1),
      workers:        this.pool.allStats(),
    };
  }

  getResult(taskId: string): TaskResult | undefined { return this.results.get(taskId); }

  // ── internals ─────────────────────────────────────────────────────────────

  private startDispatcher(): void {
    const loop = async () => {
      while (this.running || !this.queue.isEmpty) {
        if (this.queue.isEmpty) { await sleep(this.DISPATCH_MS); continue; }

        const item = this.queue.pop()!;
        const { task } = item;
        const cb = this.futures.get(task.id);

        // Skip cancelled
        if (!cb) { continue; }

        // Wait for an idle worker
        let worker: AgentWorker | null = null;
        while (!worker && this.running) {
          worker = await this.pool.acquire();
          if (!worker) await sleep(this.DISPATCH_MS);
        }
        if (!worker) continue;

        // Run with retry (non-blocking — do not await)
        this.runWithRetry(worker, task, cb);
      }
    };
    loop().catch(e => console.error("[ERROR] Dispatcher:", e));
  }

  private async runWithRetry(
    worker: AgentWorker,
    task:   Task,
    cb:     { resolve: (r: TaskResult) => void; reject: (e: Error) => void },
  ): Promise<void> {
    let result: TaskResult | null = null;
    const maxAttempts = (task.maxRetries ?? 2) + 1;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      result          = await worker.execute(task);
      result.attempts = attempt;
      if (result.status === TaskStatus.DONE) break;
      if (attempt < maxAttempts) {
        const backoff = Math.min(2 ** (attempt - 1) * 1000, 30_000);
        console.error(`[INFO] [${worker.id}] retry task ${task.id} in ${backoff}ms`);
        await sleep(backoff);
      }
    }

    if (!result) result = makeResult(task.id, worker.id, TaskStatus.FAILED, "", "no result");

    this.results.set(task.id, result);
    this.futures.delete(task.id);
    if (result.status === TaskStatus.DONE) this.totalDone++;
    else                                   this.totalFailed++;
    cb.resolve(result);
  }

  private startHealthMonitor(): void {
    const loop = async () => {
      while (this.running) {
        await sleep(this.HEALTH_MS);
        for (const s of this.pool.allStats()) {
          if (s.state === WorkerState.DEAD) {
            console.error(`[WARN] Worker ${s.id} DEAD — replacing`);
            await this.pool.replace(s.id);
          } else if (s.state === WorkerState.BUSY && s.beatAgeMs > this.STUCK_MS) {
            console.error(`[WARN] Worker ${s.id} STUCK (${s.beatAgeMs}ms) — replacing`);
            this.pool.get(s.id)?.markDead();
            await this.pool.replace(s.id);
          }
        }
      }
    };
    loop().catch(e => console.error("[ERROR] Health monitor:", e));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

if (isMainThread && process.argv[1]?.endsWith("swarmManager.ts") ||
    process.argv[1]?.endsWith("swarmManager.js")) {
  (async () => {
    const readline = await import("node:readline");
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    console.log(`
╔══════════════════════════════════════════════════════════╗
║  OMNIKON SEC·OPS — Swarm Manager  v1.0.2  (TypeScript)  ║
╚══════════════════════════════════════════════════════════╝

  submit <objective>         submit one task
  batch <o1> | <o2> …       submit multiple tasks
  metrics                    pool metrics
  quit                       shutdown
`);

    const poolSize = parseInt(process.env.POOL_SIZE ?? "3", 10);
    const swarm    = await SwarmManager.create({
      poolSize,
      elastic:  process.env.ELASTIC === "true",
      maxSize:  parseInt(process.env.MAX_SIZE ?? "20", 10),
      archiveDir: process.env.ARCHIVE_DIR,
    });

    console.log(`  Pool: ${swarm.metrics().poolSize} agents\n`);

    const ask = () => rl.question("Swarm > ", async line => {
      const [cmd, ...rest] = line.trim().split(/\s+/);
      const args = rest.join(" ");

      if (!cmd) { ask(); return; }
      switch (cmd.toLowerCase()) {
        case "quit": case "exit":
          await swarm.shutdown();
          rl.close();
          return;
        case "metrics":
          console.log(JSON.stringify(swarm.metrics(), null, 2));
          break;
        case "submit":
          if (!args) { console.log("Usage: submit <objective>"); break; }
          try {
            const r = await swarm.submit({ objective: args });
            console.log(`\n[${r.status}] ${r.latencyMs}ms\n${r.output}\n`);
          } catch(e) { console.log(`Error: ${e}`); }
          break;
        case "batch":
          const objs = args.split("|").map(o => o.trim()).filter(Boolean);
          if (!objs.length) { console.log("Usage: batch <o1> | <o2>"); break; }
          const results = await swarm.runTasks(objs.map(o => ({ objective: o })));
          for (const r of results)
            console.log(`  [${r.status}] ${r.taskId} (${r.latencyMs}ms): ${r.output.slice(0,100)}`);
          break;
        default:
          console.log(`Unknown: ${cmd}`);
      }
      ask();
    });

    rl.on("close", async () => { await swarm.shutdown(); process.exit(0); });
    ask();
  })();
}
