/**
 * =============================================================================
 * memoryManager.ts
 * =============================================================================
 * Project  : OMNIKON SEC·OPS — AI Memory System
 * Version  : v1.0.2
 * Language : TypeScript / Node.js 18+
 * License  : MIT
 *
 * Production-grade tiered AI Memory Management System — TypeScript port.
 *
 * Layers:
 *   2.1 System Memory    — hard rules / config
 *   2.2 Task Memory      — current task data
 *   2.3 Status Memory    — step / state tracker
 *   2.4 Character Memory — persona / voice / lens
 *   2.5 Reasoning Memory — ReAct loop history (activated ONLY when ReAct is on)
 *   Archive              — Append-only JSONL, async queue, atomic writes
 *
 * Runtime: Node.js 18+. Zero external dependencies.
 * =============================================================================
 */

import * as fs   from "node:fs";
import * as fsp  from "node:fs/promises";
import * as path from "node:path";
import * as crypto from "node:crypto";

// ─────────────────────────────────────────────────────────────────────────────
// Logger
// ─────────────────────────────────────────────────────────────────────────────

type LogLevel = "DEBUG" | "INFO" | "WARN" | "ERROR";
class Logger {
  constructor(private readonly name: string) {}
  private log(level: LogLevel, msg: string) {
    console.error(`${new Date().toISOString()} [${level.padEnd(5)}] ${this.name} | ${msg}`);
  }
  debug = (m: string) => this.log("DEBUG", m);
  info  = (m: string) => this.log("INFO",  m);
  warn  = (m: string) => this.log("WARN",  m);
  error = (m: string) => this.log("ERROR", m);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop-words & vector helpers
// ─────────────────────────────────────────────────────────────────────────────

const STOPWORDS = new Set([
  "a","an","the","and","or","but","in","on","at","to","for","of","with","by",
  "from","is","was","are","were","be","been","has","have","had","do","does",
  "did","not","this","that","it","its","as","so","if","then","than","can",
  "will","would","could","should","may","might","must","shall","about","into",
  "up","out","also","more","no","i","me","my","we","our","you","your",
]);

function bagOfWords(text: string): Map<string, number> {
  const bow = new Map<string, number>();
  for (const t of (text.toLowerCase().match(/[a-z0-9]{2,}/g) ?? [])) {
    if (!STOPWORDS.has(t)) bow.set(t, (bow.get(t) ?? 0) + 1);
  }
  return bow;
}

function cosine(a: Map<string, number>, b: Map<string, number>): number {
  if (!a.size || !b.size) return 0;
  let dot = 0, mA = 0, mB = 0;
  for (const [k, v] of a) { dot += v * (b.get(k) ?? 0); mA += v * v; }
  for (const v of b.values()) mB += v * v;
  return (mA === 0 || mB === 0) ? 0 : dot / (Math.sqrt(mA) * Math.sqrt(mB));
}

function utf8Truncate(text: string, maxBytes: number): string {
  const buf = Buffer.from(text, "utf8");
  return buf.length <= maxBytes ? text : buf.slice(0, maxBytes).toString("utf8").replace(/\uFFFD$/, "");
}

function tokenEstimate(text: string): number {
  return Math.floor(Buffer.byteLength(text, "utf8") / 4);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2.5  ReasoningMemory — ReAct trace + loop health monitor
// ─────────────────────────────────────────────────────────────────────────────

export type TraceType = "THOUGHT" | "ACTION" | "OBSERVATION" | "FINAL";

export interface TraceEntry {
  traceType:  TraceType;
  iteration:  number;
  content:    string;
  toolName:   string;
  isError:    boolean;
  latencyMs:  number;
  timestamp:  number;
}

export interface ReActLoopMetrics {
  totalIterations: number;
  totalToolCalls:  number;
  totalErrors:     number;
  totalLatencyMs:  number;
  startedAt:       number;
  finishedAt:      number;
  elapsedS:        number;
  avgIterMs:       number;
}

function shortTrace(t: TraceEntry): string {
  const prefix  = `[${t.traceType} i=${t.iteration}]`;
  const snippet = t.content.slice(0, 120).replace(/\n/g, " ");
  const tool    = t.toolName ? ` tool=${t.toolName}` : "";
  const err     = t.isError  ? " ⚠ERROR" : "";
  return `${prefix}${tool}${err} ${snippet}`;
}

const rmLog = new Logger("ReasoningMemory");

export class ReasoningMemory {
  static readonly PROMPT_BUDGET     = 4_000;
  static readonly MAX_ACTIVE_TRACES = 50;

  private traces:  TraceEntry[]    = [];
  private metrics: ReActLoopMetrics = ReasoningMemory.freshMetrics();
  private goal_    = "";
  private enabled_ = false;

  private static freshMetrics(): ReActLoopMetrics {
    return { totalIterations:0, totalToolCalls:0, totalErrors:0,
             totalLatencyMs:0, startedAt:Date.now()/1000, finishedAt:0,
             get elapsedS() { return Math.round(((this.finishedAt||Date.now()/1000)-this.startedAt)*100)/100; },
             get avgIterMs() { return this.totalIterations ? Math.round(this.totalLatencyMs/this.totalIterations*10)/10 : 0; } };
  }

  enable(goal = ""): void {
    this.traces  = [];
    this.metrics = ReasoningMemory.freshMetrics();
    this.goal_   = goal.trim();
    this.enabled_= true;
    rmLog.info(`enabled — goal="${this.goal_}"`);
  }

  disable(): void { this.enabled_ = false; rmLog.info("disabled"); }

  get enabled(): boolean { return this.enabled_; }
  get goal():    string  { return this.goal_; }

  record(
    traceType: TraceType, content: string,
    toolName = "", isError = false, latencyMs = 0
  ): TraceEntry {
    if (!this.enabled_) throw new Error("ReasoningMemory.record called while disabled");
    const m = this.metrics;
    m.totalIterations++;
    if (traceType === "ACTION")  m.totalToolCalls++;
    if (isError)                 m.totalErrors++;
    m.totalLatencyMs += latencyMs;

    const entry: TraceEntry = {
      traceType, iteration: m.totalIterations,
      content: content.trim(), toolName, isError, latencyMs,
      timestamp: Date.now() / 1000,
    };
    this.traces.push(entry);
    if (this.traces.length > ReasoningMemory.MAX_ACTIVE_TRACES)
      this.traces = this.traces.slice(-ReasoningMemory.MAX_ACTIVE_TRACES);

    rmLog.debug(shortTrace(entry));
    return entry;
  }

  finish(finalAnswer = ""): void {
    this.metrics.finishedAt = Date.now() / 1000;
    if (finalAnswer) this.record("FINAL", finalAnswer);
    const m = this.metrics;
    rmLog.info(`done: iters=${m.totalIterations} tools=${m.totalToolCalls} errors=${m.totalErrors} elapsed=${m.elapsedS}s`);
  }

  promptBlock(): string {
    if (!this.enabled_ || !this.traces.length) return "";
    const m = this.metrics;
    const lines = [
      "## ReAct Reasoning Trace (layer 2.5)",
      `Goal      : ${this.goal_ || "(not set)"}`,
      `Iterations: ${m.totalIterations} | Tool calls: ${m.totalToolCalls} | Errors: ${m.totalErrors} | Elapsed: ${m.elapsedS}s | Avg/iter: ${m.avgIterMs}ms`,
      "",
      "Recent steps (last 10):",
      ...this.traces.slice(-10).map(t => "  " + shortTrace(t)),
    ];
    return utf8Truncate(lines.join("\n"), ReasoningMemory.PROMPT_BUDGET);
  }

  toArchiveContent(): string {
    const m = this.metrics;
    return [
      `[ReAct Trace] goal=${JSON.stringify(this.goal_)}`,
      `iterations=${m.totalIterations} tool_calls=${m.totalToolCalls} errors=${m.totalErrors} elapsed=${m.elapsedS}s`,
      "---",
      ...this.traces.map(shortTrace),
    ].join("\n");
  }

  getTraces():          TraceEntry[]      { return [...this.traces]; }
  getMetrics():         ReActLoopMetrics  { return this.metrics; }
  lastObservation():    string {
    for (let i = this.traces.length - 1; i >= 0; i--)
      if (this.traces[i].traceType === "OBSERVATION") return this.traces[i].content;
    return "";
  }

  snapshotDict() {
    const m = this.metrics;
    return { enabled: this.enabled_, goal: this.goal_,
             totalIterations: m.totalIterations, totalToolCalls: m.totalToolCalls,
             totalErrors: m.totalErrors, elapsedS: m.elapsedS,
             avgIterMs: m.avgIterMs, traceCount: this.traces.length };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive entry
// ─────────────────────────────────────────────────────────────────────────────

const KNOWN_FIELDS = new Set(["id","timestamp","source","content","tags"]);

export interface ArchiveEntryData {
  id: string; timestamp: number; source: string; content: string; tags: string[];
}

export class ArchiveEntry implements ArchiveEntryData {
  readonly id: string; readonly timestamp: number; readonly source: string;
  readonly content: string; readonly tags: readonly string[];

  constructor(d: ArchiveEntryData) {
    if (!d.id?.trim())      throw new Error("ArchiveEntry: id must not be blank");
    if (!d.content?.trim()) throw new Error("ArchiveEntry: content must not be blank");
    this.id = d.id; this.timestamp = d.timestamp; this.source = d.source;
    this.content = d.content; this.tags = Object.freeze([...(d.tags ?? [])]);
  }

  toJsonLine(): string {
    return JSON.stringify({ id:this.id, timestamp:this.timestamp,
      source:this.source, content:this.content, tags:this.tags });
  }

  static fromJsonLine(line: string): ArchiveEntry {
    const raw = JSON.parse(line) as Record<string, unknown>;
    const clean: Partial<ArchiveEntryData> = {};
    for (const k of KNOWN_FIELDS) if (k in raw) (clean as Record<string,unknown>)[k] = raw[k];
    return new ArchiveEntry(clean as ArchiveEntryData);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaskStatus
// ─────────────────────────────────────────────────────────────────────────────

export class TaskStatus {
  objective = ""; totalSteps = 0; currentStep = 0;
  completed: string[] = []; pending: string[] = []; notes = "";

  get isActive():     boolean { return this.objective.trim().length > 0; }
  get progressPct():  number  {
    return !this.totalSteps ? 0 : Math.round(this.currentStep/this.totalSteps*1000)/10;
  }

  summary(): string {
    if (!this.isActive) return "[STATUS] No active task.";
    const prog = this.totalSteps
      ? `Step ${this.currentStep}/${this.totalSteps} (${this.progressPct}%)`
      : "—";
    const lines = [
      `[STATUS] ${prog} | Objective: ${this.objective}`,
      `  Done   : ${this.completed.join(", ") || "none"}`,
      `  Pending: ${this.pending.join(", ")   || "none"}`,
    ];
    if (this.notes) lines.push(`  Notes  : ${this.notes}`);
    return lines.join("\n");
  }

  reset() {
    this.objective=""; this.totalSteps=0; this.currentStep=0;
    this.completed=[]; this.pending=[]; this.notes="";
  }

  toJSON() {
    return { objective:this.objective, totalSteps:this.totalSteps,
             currentStep:this.currentStep, completed:this.completed,
             pending:this.pending, notes:this.notes };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CharacterMemory
// ─────────────────────────────────────────────────────────────────────────────

export class CharacterMemory {
  name = "Assistant"; tone = "professional"; expertise: string[] = [];
  personality = ""; responseFormat = "Markdown"; constraints: string[] = [];

  personaBlock(): string {
    const lines = [
      `You are ${this.name}.`, `Tone: ${this.tone}.`,
      `Expertise: ${this.expertise.join(", ") || "general"}.`,
      `Always respond in: ${this.responseFormat}.`,
    ];
    if (this.personality) lines.push(`Personality: ${this.personality}`);
    for (const c of this.constraints) lines.push(`CONSTRAINT: ${c}`);
    return lines.join("\n");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive
// ─────────────────────────────────────────────────────────────────────────────

const arcLog = new Logger("Archive");

export class Archive {
  private entries: ArchiveEntry[] = [];
  private writeQueue: Promise<void> = Promise.resolve();

  private constructor(private readonly filePath: string) {}

  static async create(filePath: string): Promise<Archive> {
    const a = new Archive(filePath);
    await a.load();
    return a;
  }

  private async load(): Promise<void> {
    if (!fs.existsSync(this.filePath)) return;
    let loaded = 0, skipped = 0;
    for (const [i, line] of (await fsp.readFile(this.filePath,"utf8")).split("\n").entries()) {
      if (!line.trim()) continue;
      try { this.entries.push(ArchiveEntry.fromJsonLine(line)); loaded++; }
      catch (e) { arcLog.warn(`corrupt line ${i+1}: ${(e as Error).message}`); skipped++; }
    }
    arcLog.info(`loaded ${loaded} (${skipped} skipped) from ${this.filePath}`);
  }

  private enqueue(op: () => Promise<void>): void {
    this.writeQueue = this.writeQueue.then(op).catch(e => arcLog.error(`write error: ${e}`));
  }

  store(content: string, source = "manual", tags: string[] = []): Promise<ArchiveEntry> {
    if (!content?.trim()) throw new Error("Archive.store: content must not be blank");
    const entry = new ArchiveEntry({
      id: crypto.randomUUID(), timestamp: Date.now()/1000,
      source, content: content.trim(), tags,
    });
    this.entries.push(entry);
    return new Promise<ArchiveEntry>((resolve, reject) =>
      this.enqueue(async () => {
        try {
          await fsp.appendFile(this.filePath, entry.toJsonLine() + "\n", "utf8");
          resolve(entry);
        } catch(e) { reject(e); }
      })
    );
  }

  retrieve(query: string, topK = 3, minScore = 0.05): ArchiveEntry[] {
    if (!query?.trim()) return [];
    const q = bagOfWords(query);
    return this.entries
      .map(e => ({ e, s: cosine(q, bagOfWords(e.content)) }))
      .filter(x => x.s >= minScore)
      .sort((a,b) => b.s - a.s)
      .slice(0, topK)
      .map(x => x.e);
  }

  async delete(id: string): Promise<boolean> {
    const before = this.entries.length;
    this.entries = this.entries.filter(e => e.id !== id);
    if (this.entries.length === before) return false;
    await new Promise<void>((res,rej) => this.enqueue(async () => {
      const tmp = this.filePath + "." + crypto.randomUUID() + ".tmp";
      try {
        await fsp.writeFile(tmp, this.entries.map(e=>e.toJsonLine()).join("\n")+"\n","utf8");
        await fsp.rename(tmp, this.filePath);
        res();
      } catch(e) { try { await fsp.unlink(tmp); } catch{} rej(e); }
    }));
    return true;
  }

  get(id: string): ArchiveEntry | undefined { return this.entries.find(e=>e.id===id); }
  allEntries(): ArchiveEntry[] { return [...this.entries]; }
  get size(): number { return this.entries.length; }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkingMemory  (layers 2.1 – 2.5)
// ─────────────────────────────────────────────────────────────────────────────

const BUDGET: Record<string,number> = {
  character: 1_500, system: 3_000, status: 1_200,
  reasoning: 4_000, retrieved: 6_000, task: 12_000,
};

const wmLog = new Logger("WorkingMemory");

export class WorkingMemory {
  static readonly SUMMARIZE_THRESHOLD = 6_000;
  keepTurns = 4;

  private systemRules:  string[]                         = [];
  private taskItems:    string[]                         = [];
  private history:      Array<{role:string;content:string}> = [];
  private _retrieved:   ArchiveEntry[]                   = [];
  readonly status    =  new TaskStatus();
  readonly character =  new CharacterMemory();
  readonly reasoning =  new ReasoningMemory();

  get retrievedCount(): number { return this._retrieved.length; }
  getSystemRules():     readonly string[]                        { return [...this.systemRules]; }
  getTaskContent():     readonly string[]                        { return [...this.taskItems]; }
  getHistory():         Array<{role:string;content:string}>      { return [...this.history]; }

  addSystemRule(rule: string): void {
    const r = rule?.trim();
    if (r && !this.systemRules.includes(r)) this.systemRules.push(r);
  }
  addTaskContent(c: string): void { if (c?.trim()) this.taskItems.push(c.trim()); }
  addMessage(role: "user"|"assistant"|"system", content: string): void {
    if (!["user","assistant","system"].includes(role)) throw new Error(`Invalid role: ${role}`);
    this.history.push({ role, content });
  }
  injectRetrieved(entries: ArchiveEntry[]): void { this._retrieved = [...entries]; }

  clearTask(): void {
    this.taskItems = []; this.history = []; this._retrieved = []; this.status.reset();
    wmLog.debug("task cleared");
  }

  popOldTurns(): Array<{role:string;content:string}> {
    if (this.history.length <= this.keepTurns) return [];
    const old = this.history.slice(0, this.history.length - this.keepTurns);
    this.history = this.history.slice(-this.keepTurns);
    return old;
  }

  private truncate(text: string, maxChars: number, label: string): string {
    if (text.length <= maxChars) return text;
    const half = Math.floor(maxChars/2);
    wmLog.warn(`layer '${label}' truncated ${text.length}→${maxChars} chars`);
    return utf8Truncate(text, half) + "\n…[truncated]…\n" + text.slice(-half);
  }

  buildSystemPrompt(): string {
    const parts: string[] = [];
    parts.push(this.truncate(this.character.personaBlock(), BUDGET.character, "character"));
    if (this.systemRules.length) {
      const block = this.systemRules.map(r=>`• ${r}`).join("\n");
      parts.push("## System Rules\n" + this.truncate(block, BUDGET.system, "system"));
    }
    if (this.status.isActive)
      parts.push(this.truncate(this.status.summary(), BUDGET.status, "status"));

    // 2.5 Reasoning — only when ReAct active
    const rb = this.reasoning.promptBlock();
    if (rb) parts.push(this.truncate(rb, BUDGET.reasoning, "reasoning"));

    if (this._retrieved.length) {
      const raw = this._retrieved.map((e,i)=>`[Memory ${i+1}] (source: ${e.source})\n${e.content}`).join("\n\n");
      parts.push("## Relevant Memory\n" + this.truncate(raw, BUDGET.retrieved, "retrieved"));
    }
    if (this.taskItems.length) {
      const raw = this.taskItems.join("\n\n");
      parts.push("## Task Context\n" + this.truncate(raw, BUDGET.task, "task"));
    }
    return parts.join("\n\n---\n\n");
  }

  buildMessages(): Array<{role:string;content:string}> { return [...this.history]; }

  tokenEstimate(): number {
    return tokenEstimate(this.buildSystemPrompt() + " " + this.history.map(m=>m.content).join(" "));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryManager
// ─────────────────────────────────────────────────────────────────────────────

const mmLog = new Logger("MemoryManager");

export interface WorkingSnapshot {
  character: Partial<CharacterMemory>;
  systemRules: string[];
  status: ReturnType<TaskStatus["toJSON"]>;
  taskContent: string[];
  conversationHistory: Array<{role:string;content:string}>;
}

export class MemoryManager {
  readonly archive: Archive;
  readonly working: WorkingMemory;

  private constructor(archive: Archive) {
    this.archive = archive;
    this.working = new WorkingMemory();
  }

  static async create(archivePath: string): Promise<MemoryManager> {
    const mm = new MemoryManager(await Archive.create(archivePath));
    mmLog.info(`initialised — ${archivePath}`);
    return mm;
  }

  // proxies
  get character():  CharacterMemory  { return this.working.character; }
  get status():     TaskStatus       { return this.working.status; }
  get react():      ReasoningMemory  { return this.working.reasoning; }

  addSystemRule(r: string):      void { this.working.addSystemRule(r); }
  addTaskContent(c: string):     void { this.working.addTaskContent(c); }
  addUserMessage(c: string):     void { this.working.addMessage("user", c); }
  addAssistantMessage(c: string):void { this.working.addMessage("assistant", c); }

  // task lifecycle
  startTask(objective: string, steps: string[] = []): void {
    if (!objective?.trim()) throw new Error("objective must not be blank");
    this.working.clearTask();
    this.working.status.objective = objective.trim();
    const clean = steps.filter(s=>s.trim());
    if (clean.length) { this.working.status.totalSteps = clean.length; this.working.status.pending = [...clean]; }
    mmLog.info(`task started: "${objective}"`);
  }

  completeStep(label?: string): void {
    const s = this.working.status;
    if (!s.isActive) throw new Error("completeStep: no active task");
    const lbl = label?.trim() ?? (s.pending[0] ?? `Step ${s.currentStep+1}`);
    if (s.pending.length) s.pending.shift();
    s.completed.push(lbl); s.currentStep++;
  }

  async finishTask(summary?: string): Promise<ArchiveEntry> {
    const s = this.working.status;
    if (!s.isActive) throw new Error("finishTask: no active task");
    const parts = [`Task: ${s.objective}`];
    if (summary?.trim()) parts.push(`Summary: ${summary.trim()}`);
    if (s.completed.length) parts.push("Completed: " + s.completed.join("; "));
    const tc = this.working.getTaskContent();
    if (tc.length) parts.push("Snapshot:\n" + tc.slice(0,3).join("\n"));
    const entry = await this.archive.store(parts.join("\n"), "task_summary", ["task", s.objective.slice(0,40)]);
    mmLog.info(`task archived: id=${entry.id}`);
    this.working.clearTask();
    return entry;
  }

  // ReAct lifecycle
  enableReact(goal = ""): void { this.working.reasoning.enable(goal); }

  async finishReact(finalAnswer = ""): Promise<ArchiveEntry | null> {
    const rm = this.working.reasoning;
    if (!rm.enabled) return null;
    rm.finish(finalAnswer);
    const content = rm.toArchiveContent();
    let entry: ArchiveEntry | null = null;
    if (content.trim()) {
      entry = await this.archive.store(content, "react_trace", ["react","reasoning", rm.goal.slice(0,40)]);
      mmLog.info(`ReAct trace archived: id=${entry.id}`);
    }
    rm.disable();
    return entry;
  }

  // context
  contextForQuery(query: string, topK = 3, minScore = 0.05): string {
    if (this.working.tokenEstimate() > WorkingMemory.SUMMARIZE_THRESHOLD)
      void this.summarizeConversation();
    const hits = this.archive.retrieve(query, topK, minScore);
    this.working.injectRetrieved(hits);
    return this.working.buildSystemPrompt();
  }

  private async summarizeConversation(): Promise<void> {
    const old = this.working.popOldTurns();
    if (!old.length) return;
    await this.archive.store(
      "[Conversation summary]\n" + old.map(m=>`${m.role.toUpperCase()}: ${m.content.slice(0,300)}`).join("\n"),
      "conversation", ["summary","auto"]
    );
    mmLog.info(`summarised ${old.length} turns`);
  }

  // snapshot
  exportSnapshot(): WorkingSnapshot {
    const c = this.working.character;
    return {
      character: { name:c.name, tone:c.tone, expertise:[...c.expertise],
                   personality:c.personality, responseFormat:c.responseFormat,
                   constraints:[...c.constraints] },
      systemRules: [...this.working.getSystemRules()],
      status: this.working.status.toJSON(),
      taskContent: [...this.working.getTaskContent()],
      conversationHistory: [...this.working.getHistory()],
    };
  }

  importSnapshot(data: Partial<WorkingSnapshot>): void {
    if (data.character) {
      const c = data.character as Partial<CharacterMemory>;
      for (const k of ["name","tone","expertise","personality","responseFormat","constraints"] as const)
        if (k in c) (this.working.character as Record<string,unknown>)[k] = c[k];
    }
    for (const r of data.systemRules ?? []) this.working.addSystemRule(r);
    if (data.status) {
      const s = data.status;
      for (const k of ["objective","totalSteps","currentStep","completed","pending","notes"] as const)
        if (k in s) (this.working.status as Record<string,unknown>)[k] = s[k];
    }
    for (const c of data.taskContent ?? []) this.working.addTaskContent(c);
    for (const m of data.conversationHistory ?? [])
      if (m.content) this.working.addMessage(m.role as "user"|"assistant"|"system", m.content);
    mmLog.info("snapshot imported");
  }

  snapshot() {
    const s = this.working.status;
    const base = {
      characterName: this.working.character.name,
      systemRuleCount: this.working.getSystemRules().length,
      taskObjective: s.objective, taskProgressPct: s.progressPct,
      taskCurrentStep: s.currentStep, taskTotalSteps: s.totalSteps,
      conversationTurns: this.working.getHistory().length,
      retrievedCount: this.working.retrievedCount,
      archiveTotal: this.archive.size,
      estimatedTokens: this.working.tokenEstimate(),
      reactEnabled: this.working.reasoning.enabled,
    };
    return this.working.reasoning.enabled
      ? { ...base, reasoning: this.working.reasoning.snapshotDict() }
      : base;
  }

  toString(): string {
    const s = this.snapshot();
    return `<MemoryManager | archive=${s.archiveTotal} | tokens≈${s.estimatedTokens} | task="${s.taskObjective}" | react=${s.reactEnabled?"ON":"OFF"}>`;
  }
}
