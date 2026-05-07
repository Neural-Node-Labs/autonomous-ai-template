// =============================================================================
// memory_manager.rs
// =============================================================================
// Project  : OMNIKON SEC·OPS — AI Memory System
// Version  : v1.0.2
// Language : Rust 1.75+
// License  : MIT
//
// Production-grade tiered AI Memory Management System — Rust implementation.
//
// Architecture
// ------------
//   ┌──────────────────────────────────────────────────────────┐
//   │  WORKING MEMORY  (context window "desk")                 │
//   │  2.1 System Memory    — hard rules / config              │
//   │  2.2 Task Memory      — current task data                │
//   │  2.3 Status Memory    — step / state tracker             │
//   │  2.4 Character Memory — persona / voice / lens           │
//   │  2.5 Reasoning Memory — ReAct loop history               │
//   │        • activated ONLY when ReAct mode is on            │
//   │        • records Thought / Action / Observation / Final  │
//   │        • surfaces compact trace into system prompt       │
//   │        • zero overhead when disabled                     │
//   └──────────────────────┬───────────────────────────────────┘
//                          │  summarize → archive
//   ┌──────────────────────▼───────────────────────────────────┐
//   │  ARCHIVE  (long-term memory)                             │
//   │  Append-only JSONL + file locking + atomic rewrite       │
//   │  Bag-of-words cosine retrieval (swap for vector DB)      │
//   └──────────────────────────────────────────────────────────┘
//
// Dependencies (Cargo.toml)
// -------------------------
//   serde / serde_json  — serialisation
//   uuid                — archive entry IDs
//   regex               — tokeniser
//   log / env_logger    — structured logging
//   parking_lot         — RwLock (faster than std)
// =============================================================================

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn utf8_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn token_estimate(text: &str) -> usize {
    text.len() / 4
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop-words & vector helpers
// ─────────────────────────────────────────────────────────────────────────────

const STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for", "of",
    "with", "by", "from", "is", "was", "are", "were", "be", "been", "has", "have",
    "had", "do", "does", "did", "not", "this", "that", "it", "its", "as", "so",
    "if", "then", "than", "can", "will", "would", "could", "should", "may",
    "might", "must", "shall", "about", "into", "up", "out", "also", "more", "no",
    "i", "me", "my", "we", "our", "you", "your",
];

fn is_stopword(token: &str) -> bool {
    STOPWORDS.binary_search(&token).is_ok()
}

fn bag_of_words(text: &str) -> HashMap<String, u32> {
    let re = Regex::new(r"[a-z0-9]{2,}").unwrap();
    let lower = text.to_lowercase();
    let mut bow = HashMap::new();
    for m in re.find_iter(&lower) {
        let tok = m.as_str();
        if !is_stopword(tok) {
            *bow.entry(tok.to_string()).or_insert(0) += 1;
        }
    }
    bow
}

fn cosine_sim(a: &HashMap<String, u32>, b: &HashMap<String, u32>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let dot: f64 = a
        .iter()
        .filter_map(|(k, v)| b.get(k).map(|bv| (*v as f64) * (*bv as f64)))
        .sum();
    if dot == 0.0 {
        return 0.0;
    }
    let mag_a: f64 = a.values().map(|v| (*v as f64).powi(2)).sum::<f64>().sqrt();
    let mag_b: f64 = b.values().map(|v| (*v as f64).powi(2)).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        0.0
    } else {
        dot / (mag_a * mag_b)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2.5  ReasoningMemory — ReAct trace + loop health monitor
// ─────────────────────────────────────────────────────────────────────────────

/// The four canonical ReAct step types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceType {
    Thought,
    Action,
    Observation,
    Final,
}

impl TraceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TraceType::Thought     => "THOUGHT",
            TraceType::Action      => "ACTION",
            TraceType::Observation => "OBSERVATION",
            TraceType::Final       => "FINAL",
        }
    }
}

/// One step in the ReAct execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub trace_type: String,
    pub iteration:  u32,
    pub content:    String,
    pub tool_name:  String,
    pub is_error:   bool,
    pub latency_ms: u64,
    pub timestamp:  f64,
}

impl TraceEntry {
    pub fn short(&self) -> String {
        let prefix  = format!("[{} i={}]", self.trace_type, self.iteration);
        let snippet: String = self.content.chars().take(120).collect::<String>()
            .replace('\n', " ");
        let tool = if self.tool_name.is_empty() { String::new() } else { format!(" tool={}", self.tool_name) };
        let err  = if self.is_error { " ⚠ERROR" } else { "" };
        format!("{}{}{} {}", prefix, tool, err, snippet)
    }
}

/// Aggregate counters for one ReAct session.
#[derive(Debug, Clone, Default)]
pub struct ReActLoopMetrics {
    pub total_iterations: u32,
    pub total_tool_calls: u32,
    pub total_errors:     u32,
    pub total_latency_ms: u64,
    pub started_at:       f64,
    pub finished_at:      f64,
}

impl ReActLoopMetrics {
    pub fn new() -> Self {
        Self { started_at: now_secs(), ..Default::default() }
    }

    pub fn elapsed_s(&self) -> f64 {
        let end = if self.finished_at > 0.0 { self.finished_at } else { now_secs() };
        ((end - self.started_at) * 100.0).round() / 100.0
    }

    pub fn avg_iter_ms(&self) -> f64 {
        if self.total_iterations == 0 { 0.0 }
        else { (self.total_latency_ms as f64 / self.total_iterations as f64 * 10.0).round() / 10.0 }
    }
}

/// Memory layer 2.5 — activated ONLY when ReAct mode is on.
///
/// Thread-safe via `RwLock`. Zero overhead when disabled.
pub struct ReasoningMemory {
    inner: RwLock<ReasoningMemoryInner>,
}

struct ReasoningMemoryInner {
    traces:   Vec<TraceEntry>,
    metrics:  ReActLoopMetrics,
    goal:     String,
    enabled:  bool,
}

impl Default for ReasoningMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl ReasoningMemory {
    const PROMPT_BUDGET:     usize = 4_000;
    const MAX_ACTIVE_TRACES: usize = 50;

    pub fn new() -> Self {
        Self {
            inner: RwLock::new(ReasoningMemoryInner {
                traces:  Vec::new(),
                metrics: ReActLoopMetrics::new(),
                goal:    String::new(),
                enabled: false,
            }),
        }
    }

    /// Activate and reset for a fresh ReAct session.
    pub fn enable(&self, goal: &str) {
        let mut g = self.inner.write();
        g.enabled = true;
        g.traces.clear();
        g.metrics = ReActLoopMetrics::new();
        g.goal    = goal.trim().to_string();
        log::info!("ReasoningMemory: enabled — goal={:?}", g.goal);
    }

    /// Deactivate — layer 2.5 goes dark.
    pub fn disable(&self) {
        self.inner.write().enabled = false;
        log::info!("ReasoningMemory: disabled.");
    }

    pub fn is_enabled(&self) -> bool { self.inner.read().enabled }
    pub fn goal(&self)       -> String { self.inner.read().goal.clone() }

    /// Record one ReAct step. Returns the created entry.
    /// Panics if called while disabled.
    pub fn record(
        &self,
        trace_type: TraceType,
        content:    &str,
        tool_name:  &str,
        is_error:   bool,
        latency_ms: u64,
    ) -> TraceEntry {
        let mut g = self.inner.write();
        assert!(g.enabled, "ReasoningMemory::record called while disabled");

        g.metrics.total_iterations += 1;
        if trace_type == TraceType::Action { g.metrics.total_tool_calls += 1; }
        if is_error                        { g.metrics.total_errors     += 1; }
        g.metrics.total_latency_ms += latency_ms;

        let entry = TraceEntry {
            trace_type: trace_type.as_str().to_string(),
            iteration:  g.metrics.total_iterations,
            content:    content.trim().to_string(),
            tool_name:  tool_name.to_string(),
            is_error,
            latency_ms,
            timestamp:  now_secs(),
        };
        g.traces.push(entry.clone());
        if g.traces.len() > Self::MAX_ACTIVE_TRACES {
            let drain_to = g.traces.len() - Self::MAX_ACTIVE_TRACES;
            g.traces.drain(..drain_to);
        }
        log::debug!("ReAct: {}", entry.short());
        entry
    }

    /// Convenience: record with no tool / no error / no latency.
    pub fn record_simple(&self, trace_type: TraceType, content: &str) -> TraceEntry {
        self.record(trace_type, content, "", false, 0)
    }

    /// Mark the loop complete and optionally record a final answer.
    pub fn finish(&self, final_answer: &str) {
        {
            let mut g = self.inner.write();
            g.metrics.finished_at = now_secs();
        }
        if !final_answer.is_empty() {
            self.record_simple(TraceType::Final, final_answer);
        }
        let g = self.inner.read();
        log::info!(
            "ReAct done: iters={} tools={} errors={} elapsed={:.2}s",
            g.metrics.total_iterations, g.metrics.total_tool_calls,
            g.metrics.total_errors,     g.metrics.elapsed_s()
        );
    }

    /// Return the text block injected into the system prompt.
    /// Empty string when disabled or no traces yet.
    pub fn prompt_block(&self) -> String {
        let g = self.inner.read();
        if !g.enabled || g.traces.is_empty() { return String::new(); }
        let m = &g.metrics;
        let mut lines = vec![
            "## ReAct Reasoning Trace (layer 2.5)".to_string(),
            format!("Goal      : {}", if g.goal.is_empty() { "(not set)" } else { &g.goal }),
            format!(
                "Iterations: {} | Tool calls: {} | Errors: {} | Elapsed: {:.2}s | Avg/iter: {:.1}ms",
                m.total_iterations, m.total_tool_calls, m.total_errors, m.elapsed_s(), m.avg_iter_ms()
            ),
            String::new(),
            "Recent steps (last 10):".to_string(),
        ];
        let start = g.traces.len().saturating_sub(10);
        for t in &g.traces[start..] {
            lines.push(format!("  {}", t.short()));
        }
        let block = lines.join("\n");
        utf8_truncate(&block, Self::PROMPT_BUDGET).to_string()
    }

    /// Serialise the full trace for archiving.
    pub fn to_archive_content(&self) -> String {
        let g = self.inner.read();
        let m = &g.metrics;
        let mut lines = vec![
            format!("[ReAct Trace] goal={:?}", g.goal),
            format!(
                "iterations={} tool_calls={} errors={} elapsed={:.2}s",
                m.total_iterations, m.total_tool_calls, m.total_errors, m.elapsed_s()
            ),
            "---".to_string(),
        ];
        for t in &g.traces { lines.push(t.short()); }
        lines.join("\n")
    }

    pub fn traces(&self)  -> Vec<TraceEntry>     { self.inner.read().traces.clone() }
    pub fn metrics(&self) -> ReActLoopMetrics     { self.inner.read().metrics.clone() }

    /// Content of the most recent OBSERVATION, or empty string.
    pub fn last_observation(&self) -> String {
        let g = self.inner.read();
        g.traces.iter().rev()
            .find(|t| t.trace_type == "OBSERVATION")
            .map(|t| t.content.clone())
            .unwrap_or_default()
    }

    pub fn snapshot(&self) -> ReasoningSnapshot {
        let g = self.inner.read();
        let m = &g.metrics;
        ReasoningSnapshot {
            enabled:          g.enabled,
            goal:             g.goal.clone(),
            total_iterations: m.total_iterations,
            total_tool_calls: m.total_tool_calls,
            total_errors:     m.total_errors,
            elapsed_s:        m.elapsed_s(),
            avg_iter_ms:      m.avg_iter_ms(),
            trace_count:      g.traces.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReasoningSnapshot {
    pub enabled:          bool,
    pub goal:             String,
    pub total_iterations: u32,
    pub total_tool_calls: u32,
    pub total_errors:     u32,
    pub elapsed_s:        f64,
    pub avg_iter_ms:      f64,
    pub trace_count:      usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchiveEntry
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub id:        String,
    pub timestamp: f64,
    pub source:    String,
    pub content:   String,
    pub tags:      Vec<String>,
}

impl ArchiveEntry {
    pub fn new(content: &str, source: &str, tags: Vec<String>) -> Self {
        assert!(!content.trim().is_empty(), "ArchiveEntry: content must not be empty");
        Self {
            id:        Uuid::new_v4().to_string(),
            timestamp: now_secs(),
            source:    source.to_string(),
            content:   content.trim().to_string(),
            tags,
        }
    }

    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).expect("ArchiveEntry serialisation failed")
    }

    pub fn from_jsonl(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive — long-term memory (thread-safe JSONL store)
// ─────────────────────────────────────────────────────────────────────────────

pub struct Archive {
    path:    PathBuf,
    entries: RwLock<Vec<ArchiveEntry>>,
}

impl Archive {
    /// Open (or create) an archive at `path`. Loads existing entries.
    pub fn open(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let entries = Self::load_from_disk(&path);
        Self { path, entries: RwLock::new(entries) }
    }

    fn load_from_disk(path: &Path) -> Vec<ArchiveEntry> {
        if !path.exists() { return Vec::new(); }
        let file = match File::open(path) {
            Ok(f)  => f,
            Err(e) => { log::error!("Archive: cannot open {}: {}", path.display(), e); return Vec::new(); }
        };
        let mut loaded = 0usize;
        let mut skipped = 0usize;
        let entries = BufReader::new(file)
            .lines()
            .enumerate()
            .filter_map(|(i, line)| {
                let line = line.ok()?;
                let line = line.trim();
                if line.is_empty() { return None; }
                match ArchiveEntry::from_jsonl(line) {
                    Ok(e)  => { loaded += 1; Some(e) }
                    Err(e) => {
                        log::warn!("Archive: corrupt line {}: {}", i + 1, e);
                        skipped += 1;
                        None
                    }
                }
            })
            .collect();
        log::info!("Archive: loaded {} entries ({} skipped) from {}", loaded, skipped, path.display());
        entries
    }

    fn append_to_disk(&self, entry: &ArchiveEntry) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true).append(true).open(&self.path)?;
        writeln!(file, "{}", entry.to_jsonl())?;
        file.flush()?;
        Ok(())
    }

    fn rewrite_disk(&self, entries: &[ArchiveEntry]) -> std::io::Result<()> {
        // Write to temp file then atomic rename
        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut file = File::create(&tmp)?;
            for e in entries {
                writeln!(file, "{}", e.to_jsonl())?;
            }
            file.flush()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Store a new entry. Returns a clone of the created entry.
    pub fn store(&self, content: &str, source: &str, tags: Vec<String>) -> ArchiveEntry {
        assert!(!content.trim().is_empty(), "Archive.store: content must not be empty");
        let entry = ArchiveEntry::new(content, source, tags);
        let mut w = self.entries.write();
        w.push(entry.clone());
        if let Err(e) = self.append_to_disk(&entry) {
            log::error!("Archive.store: disk write failed: {}", e);
        }
        log::debug!("Archive.store: id={} source={}", entry.id, entry.source);
        entry
    }

    /// Cosine-similarity retrieval. Override this method for a real vector DB.
    pub fn retrieve(&self, query: &str, top_k: usize, min_score: f64) -> Vec<ArchiveEntry> {
        if query.trim().is_empty() { return Vec::new(); }
        let q_vec = bag_of_words(query);
        let r = self.entries.read();
        let mut scored: Vec<(&ArchiveEntry, f64)> = r
            .iter()
            .map(|e| (e, cosine_sim(&q_vec, &bag_of_words(&e.content))))
            .filter(|(_, s)| *s >= min_score)
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(top_k).map(|(e, _)| e.clone()).collect()
    }

    /// Delete by id. Rewrites the file atomically on success.
    pub fn delete(&self, id: &str) -> bool {
        let mut w = self.entries.write();
        let before = w.len();
        w.retain(|e| e.id != id);
        if w.len() == before { return false; }
        if let Err(e) = self.rewrite_disk(&w) {
            log::error!("Archive.delete: rewrite failed: {}", e);
        }
        true
    }

    pub fn get(&self, id: &str) -> Option<ArchiveEntry> {
        self.entries.read().iter().find(|e| e.id == id).cloned()
    }

    pub fn all_entries(&self) -> Vec<ArchiveEntry> { self.entries.read().clone() }
    pub fn len(&self) -> usize { self.entries.read().len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaskStatus
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskStatus {
    pub objective:    String,
    pub total_steps:  u32,
    pub current_step: u32,
    pub completed:    Vec<String>,
    pub pending:      Vec<String>,
    pub notes:        String,
}

impl TaskStatus {
    pub fn is_active(&self)    -> bool { !self.objective.trim().is_empty() }
    pub fn progress_pct(&self) -> f64 {
        if self.total_steps == 0 { 0.0 }
        else { (self.current_step as f64 / self.total_steps as f64 * 1000.0).round() / 10.0 }
    }

    pub fn summary(&self) -> String {
        if !self.is_active() { return "[STATUS] No active task.".to_string(); }
        let prog = if self.total_steps > 0 {
            format!("Step {}/{} ({:.1}%)", self.current_step, self.total_steps, self.progress_pct())
        } else { "—".to_string() };
        let done    = if self.completed.is_empty() { "none".to_string() } else { self.completed.join(", ") };
        let pending = if self.pending.is_empty()   { "none".to_string() } else { self.pending.join(", ") };
        let mut s = format!(
            "[STATUS] {} | Objective: {}\n  Done   : {}\n  Pending: {}",
            prog, self.objective, done, pending
        );
        if !self.notes.is_empty() { s.push_str(&format!("\n  Notes  : {}", self.notes)); }
        s
    }

    pub fn reset(&mut self) {
        *self = TaskStatus::default();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CharacterMemory
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterMemory {
    pub name:            String,
    pub tone:            String,
    pub expertise:       Vec<String>,
    pub personality:     String,
    pub response_format: String,
    pub constraints:     Vec<String>,
}

impl Default for CharacterMemory {
    fn default() -> Self {
        Self {
            name:            "Assistant".to_string(),
            tone:            "professional".to_string(),
            expertise:       Vec::new(),
            personality:     String::new(),
            response_format: "Markdown".to_string(),
            constraints:     Vec::new(),
        }
    }
}

impl CharacterMemory {
    pub fn persona_block(&self) -> String {
        let exp = if self.expertise.is_empty() { "general".to_string() } else { self.expertise.join(", ") };
        let mut lines = vec![
            format!("You are {}.", self.name),
            format!("Tone: {}.",   self.tone),
            format!("Expertise: {}.", exp),
            format!("Always respond in: {}.", self.response_format),
        ];
        if !self.personality.is_empty() { lines.push(format!("Personality: {}", self.personality)); }
        for c in &self.constraints { lines.push(format!("CONSTRAINT: {}", c)); }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkingMemory — layers 2.1 – 2.5
// ─────────────────────────────────────────────────────────────────────────────

const BUDGET_CHARACTER: usize = 1_500;
const BUDGET_SYSTEM:    usize = 3_000;
const BUDGET_STATUS:    usize = 1_200;
const BUDGET_REASONING: usize = 4_000;
const BUDGET_RETRIEVED: usize = 6_000;
const BUDGET_TASK:      usize = 12_000;

pub struct WorkingMemory {
    inner:     RwLock<WorkingMemoryInner>,
    pub reasoning: Arc<ReasoningMemory>,
}

struct WorkingMemoryInner {
    system_rules:  Vec<String>,
    task_content:  Vec<String>,
    history:       Vec<Message>,
    status:        TaskStatus,
    character:     CharacterMemory,
    retrieved:     Vec<ArchiveEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role:    String,
    pub content: String,
}

impl WorkingMemory {
    pub const SUMMARIZE_THRESHOLD: usize = 6_000;
    pub const KEEP_TURNS:          usize = 4;

    pub fn new() -> Self {
        Self {
            inner: RwLock::new(WorkingMemoryInner {
                system_rules: Vec::new(),
                task_content: Vec::new(),
                history:      Vec::new(),
                status:       TaskStatus::default(),
                character:    CharacterMemory::default(),
                retrieved:    Vec::new(),
            }),
            reasoning: Arc::new(ReasoningMemory::new()),
        }
    }

    // ── accessors ────────────────────────────────────────────────────────────

    pub fn with_character<F, R>(&self, f: F) -> R where F: FnOnce(&CharacterMemory) -> R {
        f(&self.inner.read().character)
    }
    pub fn with_character_mut<F>(&self, f: F) where F: FnOnce(&mut CharacterMemory) {
        f(&mut self.inner.write().character)
    }
    pub fn with_status<F, R>(&self, f: F) -> R where F: FnOnce(&TaskStatus) -> R {
        f(&self.inner.read().status)
    }
    pub fn with_status_mut<F>(&self, f: F) where F: FnOnce(&mut TaskStatus) {
        f(&mut self.inner.write().status)
    }
    pub fn system_rules(&self)  -> Vec<String>  { self.inner.read().system_rules.clone() }
    pub fn task_content(&self)  -> Vec<String>  { self.inner.read().task_content.clone() }
    pub fn history(&self)       -> Vec<Message> { self.inner.read().history.clone() }
    pub fn retrieved_count(&self) -> usize      { self.inner.read().retrieved.len() }

    // ── mutators ─────────────────────────────────────────────────────────────

    pub fn add_system_rule(&self, rule: &str) {
        let r = rule.trim();
        if r.is_empty() { return; }
        let mut w = self.inner.write();
        if !w.system_rules.iter().any(|x| x == r) {
            w.system_rules.push(r.to_string());
        }
    }

    pub fn add_task_content(&self, content: &str) {
        let c = content.trim();
        if !c.is_empty() { self.inner.write().task_content.push(c.to_string()); }
    }

    pub fn add_message(&self, role: &str, content: &str) {
        assert!(matches!(role, "user" | "assistant" | "system"), "Invalid role: {}", role);
        self.inner.write().history.push(Message { role: role.to_string(), content: content.to_string() });
    }

    pub fn inject_retrieved(&self, entries: Vec<ArchiveEntry>) {
        self.inner.write().retrieved = entries;
    }

    pub fn clear_task(&self) {
        let mut w = self.inner.write();
        w.task_content.clear();
        w.history.clear();
        w.retrieved.clear();
        w.status.reset();
        log::debug!("WorkingMemory: task cleared.");
    }

    pub fn pop_old_turns(&self) -> Vec<Message> {
        let mut w = self.inner.write();
        if w.history.len() <= Self::KEEP_TURNS { return Vec::new(); }
        let split = w.history.len() - Self::KEEP_TURNS;
        let old: Vec<Message> = w.history.drain(..split).collect();
        old
    }

    // ── prompt assembly ───────────────────────────────────────────────────────

    fn truncate(text: &str, max_chars: usize, label: &str) -> String {
        if text.len() <= max_chars { return text.to_string(); }
        let half = max_chars / 2;
        log::warn!("WorkingMemory: '{}' truncated {}→{} chars", label, text.len(), max_chars);
        let head = utf8_truncate(text, half).to_string();
        let tail = &text[text.len().saturating_sub(half)..];
        format!("{}\n…[truncated]…\n{}", head, tail)
    }

    pub fn build_system_prompt(&self) -> String {
        let g = self.inner.read();
        let mut parts: Vec<String> = Vec::new();

        // 2.4 Character
        parts.push(Self::truncate(&g.character.persona_block(), BUDGET_CHARACTER, "character"));

        // 2.1 System rules
        if !g.system_rules.is_empty() {
            let block = g.system_rules.iter().map(|r| format!("• {}", r)).collect::<Vec<_>>().join("\n");
            parts.push(format!("## System Rules\n{}", Self::truncate(&block, BUDGET_SYSTEM, "system")));
        }

        // 2.3 Status
        if g.status.is_active() {
            parts.push(Self::truncate(&g.status.summary(), BUDGET_STATUS, "status"));
        }

        // 2.5 Reasoning — only when ReAct active
        let rb = self.reasoning.prompt_block();
        if !rb.is_empty() {
            parts.push(Self::truncate(&rb, BUDGET_REASONING, "reasoning"));
        }

        // Retrieved archive
        if !g.retrieved.is_empty() {
            let raw = g.retrieved.iter().enumerate()
                .map(|(i, e)| format!("[Memory {}] (source: {})\n{}", i + 1, e.source, e.content))
                .collect::<Vec<_>>().join("\n\n");
            parts.push(format!("## Relevant Memory\n{}", Self::truncate(&raw, BUDGET_RETRIEVED, "retrieved")));
        }

        // 2.2 Task content
        if !g.task_content.is_empty() {
            let raw = g.task_content.join("\n\n");
            parts.push(format!("## Task Context\n{}", Self::truncate(&raw, BUDGET_TASK, "task")));
        }

        parts.join("\n\n---\n\n")
    }

    pub fn build_messages(&self) -> Vec<Message> {
        self.inner.read().history.clone()
    }

    pub fn token_estimate(&self) -> usize {
        let g = self.inner.read();
        let hist: String = g.history.iter().map(|m| m.content.as_str()).collect::<Vec<_>>().join(" ");
        drop(g);
        let prompt = self.build_system_prompt();
        token_estimate(&format!("{} {}", prompt, hist))
    }
}

impl Default for WorkingMemory {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryManager — unified orchestrator
// ─────────────────────────────────────────────────────────────────────────────

pub struct MemoryManager {
    pub archive: Archive,
    pub working: WorkingMemory,
}

impl MemoryManager {
    /// Create a new MemoryManager backed by `archive_path`.
    pub fn new(archive_path: impl AsRef<Path>) -> Self {
        let mm = Self {
            archive: Archive::open(&archive_path),
            working: WorkingMemory::new(),
        };
        log::info!("MemoryManager v1.0.2 ready. Archive: {}", archive_path.as_ref().display());
        mm
    }

    // ── proxies ───────────────────────────────────────────────────────────────

    pub fn add_system_rule(&self, rule: &str)      { self.working.add_system_rule(rule); }
    pub fn add_task_content(&self, content: &str)  { self.working.add_task_content(content); }
    pub fn add_user_message(&self, content: &str)  { self.working.add_message("user", content); }
    pub fn add_assistant_message(&self, c: &str)   { self.working.add_message("assistant", c); }

    // ── task lifecycle ────────────────────────────────────────────────────────

    /// Start a new task, clearing previous working state.
    pub fn start_task(&self, objective: &str, steps: Vec<String>) {
        assert!(!objective.trim().is_empty(), "start_task: objective must not be empty");
        self.working.clear_task();
        self.working.with_status_mut(|s| {
            s.objective  = objective.trim().to_string();
            let clean: Vec<String> = steps.iter().filter(|s| !s.trim().is_empty()).cloned().collect();
            s.total_steps = clean.len() as u32;
            s.pending     = clean;
        });
        log::info!("Task started: {:?}", objective);
    }

    /// Mark the next pending step complete.
    pub fn complete_step(&self, label: Option<&str>) {
        self.working.with_status_mut(|s| {
            assert!(s.is_active(), "complete_step: no active task");
            let lbl = label.filter(|l| !l.trim().is_empty())
                .map(|l| l.to_string())
                .unwrap_or_else(|| {
                    s.pending.first().cloned()
                        .unwrap_or_else(|| format!("Step {}", s.current_step + 1))
                });
            if !s.pending.is_empty() { s.pending.remove(0); }
            s.completed.push(lbl);
            s.current_step += 1;
        });
    }

    /// Archive the completed task and clear working memory.
    pub fn finish_task(&self, summary: Option<&str>) -> ArchiveEntry {
        let (objective, completed) = self.working.with_status(|s| {
            assert!(s.is_active(), "finish_task: no active task");
            (s.objective.clone(), s.completed.clone())
        });
        let mut parts = vec![format!("Task: {}", objective)];
        if let Some(s) = summary { if !s.trim().is_empty() { parts.push(format!("Summary: {}", s.trim())); } }
        if !completed.is_empty() { parts.push(format!("Completed: {}", completed.join("; "))); }
        let tc = self.working.task_content();
        if !tc.is_empty() { parts.push(format!("Snapshot:\n{}", tc[..tc.len().min(3)].join("\n"))); }

        let entry = self.archive.store(
            &parts.join("\n"), "task_summary",
            vec!["task".to_string(), objective[..objective.len().min(40)].to_string()],
        );
        log::info!("Task archived: id={}", entry.id);
        self.working.clear_task();
        entry
    }

    // ── ReAct lifecycle ───────────────────────────────────────────────────────

    /// Activate ReasoningMemory (layer 2.5) for a new ReAct session.
    pub fn enable_react(&self, goal: &str) {
        self.working.reasoning.enable(goal);
    }

    /// Close ReAct loop: record final answer, archive trace, disable layer 2.5.
    pub fn finish_react(&self, final_answer: &str) -> Option<ArchiveEntry> {
        let rm = &self.working.reasoning;
        if !rm.is_enabled() { return None; }
        rm.finish(final_answer);
        let content = rm.to_archive_content();
        let entry = if !content.trim().is_empty() {
            let goal = rm.goal();
            let e = self.archive.store(
                &content, "react_trace",
                vec!["react".to_string(), "reasoning".to_string(), goal[..goal.len().min(40)].to_string()],
            );
            log::info!("ReAct trace archived: id={}", e.id);
            Some(e)
        } else { None };
        rm.disable();
        entry
    }

    // ── context assembly ──────────────────────────────────────────────────────

    /// Retrieve relevant archive entries for `query`, inject them into working
    /// memory, auto-summarise if over budget, and return the system prompt.
    pub fn context_for_query(&self, query: &str, top_k: usize, min_score: f64) -> String {
        if self.working.token_estimate() > WorkingMemory::SUMMARIZE_THRESHOLD {
            self.summarize_conversation();
        }
        let hits = self.archive.retrieve(query, top_k, min_score);
        self.working.inject_retrieved(hits);
        self.working.build_system_prompt()
    }

    fn summarize_conversation(&self) {
        let old = self.working.pop_old_turns();
        if old.is_empty() { return; }
        let lines: Vec<String> = old.iter()
            .map(|m| format!("{}: {}", m.role.to_uppercase(), &m.content[..m.content.len().min(300)]))
            .collect();
        self.archive.store(
            &format!("[Conversation summary]\n{}", lines.join("\n")),
            "conversation",
            vec!["summary".to_string(), "auto".to_string()],
        );
        log::info!("Summarised {} turns into archive.", old.len());
    }

    // ── snapshot ──────────────────────────────────────────────────────────────

    pub fn snapshot(&self) -> MemorySnapshot {
        let react = self.working.reasoning.snapshot();
        let (objective, progress, current, total, pending, completed) =
            self.working.with_status(|s| (
                s.objective.clone(), s.progress_pct(),
                s.current_step, s.total_steps,
                s.pending.len(), s.completed.len(),
            ));
        MemorySnapshot {
            character_name:    self.working.with_character(|c| c.name.clone()),
            system_rule_count: self.working.system_rules().len(),
            task_objective:    objective,
            task_progress_pct: progress,
            task_current_step: current,
            task_total_steps:  total,
            task_pending:      pending,
            task_completed:    completed,
            conversation_turns:self.working.history().len(),
            retrieved_count:   self.working.retrieved_count(),
            archive_total:     self.archive.len(),
            estimated_tokens:  self.working.token_estimate(),
            react_enabled:     react.enabled,
            reasoning:         if react.enabled { Some(react) } else { None },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MemorySnapshot {
    pub character_name:     String,
    pub system_rule_count:  usize,
    pub task_objective:     String,
    pub task_progress_pct:  f64,
    pub task_current_step:  u32,
    pub task_total_steps:   u32,
    pub task_pending:       usize,
    pub task_completed:     usize,
    pub conversation_turns: usize,
    pub retrieved_count:    usize,
    pub archive_total:      usize,
    pub estimated_tokens:   usize,
    pub react_enabled:      bool,
    pub reasoning:          Option<ReasoningSnapshot>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn tmp_mm() -> (MemoryManager, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let mm = MemoryManager::new(f.path());
        (mm, f)
    }

    #[test]
    fn test_archive_store_retrieve() {
        let (mm, _f) = tmp_mm();
        mm.archive.store("SQL injection CVE-2024-1234", "kb", vec!["cve".to_string()]);
        let hits = mm.archive.retrieve("SQL injection", 1, 0.05);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].content.contains("SQL"));
    }

    #[test]
    fn test_archive_empty_query() {
        let (mm, _f) = tmp_mm();
        mm.archive.store("some content", "manual", vec![]);
        assert!(mm.archive.retrieve("", 3, 0.05).is_empty());
    }

    #[test]
    fn test_archive_delete() {
        let (mm, _f) = tmp_mm();
        let e = mm.archive.store("to be deleted", "test", vec![]);
        assert!(mm.archive.delete(&e.id));
        assert!(mm.archive.get(&e.id).is_none());
        assert!(!mm.archive.delete("nonexistent-id"));
    }

    #[test]
    fn test_task_lifecycle() {
        let (mm, _f) = tmp_mm();
        mm.start_task("Test task", vec!["step1".to_string(), "step2".to_string()]);
        assert!(mm.working.with_status(|s| s.is_active()));
        mm.complete_step(None);
        let (current, completed) = mm.working.with_status(|s| (s.current_step, s.completed.clone()));
        assert_eq!(current, 1);
        assert_eq!(completed, vec!["step1"]);
        let e = mm.finish_task(Some("done"));
        assert_eq!(e.source, "task_summary");
        assert!(!mm.working.with_status(|s| s.is_active()));
    }

    #[test]
    #[should_panic(expected = "no active task")]
    fn test_finish_task_no_active() {
        let (mm, _f) = tmp_mm();
        mm.finish_task(None);
    }

    #[test]
    fn test_reasoning_memory() {
        let (mm, _f) = tmp_mm();
        mm.enable_react("test goal");
        assert!(mm.working.reasoning.is_enabled());
        mm.working.reasoning.record(TraceType::Thought, "thinking", "", false, 100);
        mm.working.reasoning.record(TraceType::Action,  "tool_x args", "tool_x", false, 50);
        mm.working.reasoning.record(TraceType::Observation, "result", "", false, 20);
        let snap = mm.working.reasoning.snapshot();
        assert_eq!(snap.total_iterations, 3);
        assert_eq!(snap.total_tool_calls, 1);
        assert_eq!(snap.total_errors, 0);
        let block = mm.working.reasoning.prompt_block();
        assert!(block.contains("ReAct Reasoning Trace"));
        let entry = mm.finish_react("final answer");
        assert!(entry.is_some());
        assert!(!mm.working.reasoning.is_enabled());
    }

    #[test]
    fn test_dedup_system_rules() {
        let (mm, _f) = tmp_mm();
        mm.add_system_rule("Rule A");
        mm.add_system_rule("Rule A");
        assert_eq!(mm.working.system_rules().len(), 1);
    }

    #[test]
    fn test_corrupt_jsonl_resilience() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            "{\"id\":\"a\",\"timestamp\":1.0,\"source\":\"s\",\"content\":\"good\",\"tags\":[]}\nNOT JSON\n{\"id\":\"b\",\"timestamp\":2.0,\"source\":\"s\",\"content\":\"also good\",\"tags\":[]}\n"
        ).unwrap();
        let arc = Archive::open(f.path());
        assert_eq!(arc.len(), 2);
    }

    #[test]
    fn test_cosine_stopwords() {
        // "the" and "a" are stopwords — should not affect similarity
        let a = bag_of_words("the quick brown fox");
        let b = bag_of_words("a quick brown fox");
        // "quick" and "brown" and "fox" should match
        let score = cosine_sim(&a, &b);
        assert!(score > 0.9, "score={}", score);
    }

    #[test]
    fn test_utf8_truncate() {
        let s = "héllo wörld";
        let t = utf8_truncate(s, 5);
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }
}
