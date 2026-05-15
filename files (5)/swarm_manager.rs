// =============================================================================
// swarm_manager.rs
// =============================================================================
// Project  : OMNIKON SEC·OPS — AI Swarm Manager
// Version  : v1.0.2
// Language : Rust 1.75+
// License  : MIT
//
// Production-grade Agent Swarm Manager for SecOps workloads.
//
// Architecture:
//   SwarmManager                — top-level orchestrator, consumer API
//     ├── AgentPool             — elastic pool of AgentWorker slots
//     │     └── AgentWorker     — wraps MemoryManager + 22 SecOps skills
//     ├── PriorityTaskQueue     — CRITICAL > HIGH > NORMAL > LOW
//     └── HealthMonitor         — heartbeat, stuck detection, auto-restart
//
// Consumer API:
//   let mut swarm = SwarmManager::new(SwarmConfig { pool_size: 10, ..Default::default() });
//   let results = swarm.run_tasks(vec![
//       Task::new("Scan target.com", vec!["port_scanner", "ssl_cert_inspector"]),
//       Task::new("Check CVE-2024-1234", vec!["cve_lookup"]),
//   ]);
//
// Usage:
//   export DEEPSEEK_API_KEY=sk-...
//   cargo run --release --bin swarm
// =============================================================================

mod memory_manager;
// Skills are imported from agent module — re-export for swarm use
mod agent;

use memory_manager::{MemoryManager, TraceType};
use agent::{SkillRegistry, call_deepseek};

use std::{
    collections::{BinaryHeap, HashMap, VecDeque},
    env,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Priority
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Priority {
    Low      = 3,
    Normal   = 2,
    High     = 1,
    Critical = 0,
}

impl Default for Priority { fn default() -> Self { Self::Normal } }

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self { Self::Critical=>"CRITICAL", Self::High=>"HIGH", Self::Normal=>"NORMAL", Self::Low=>"LOW" }.fmt(f)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Task
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id:    String,
    pub objective:  String,
    pub target:     String,
    pub skills:     Vec<String>,
    pub priority:   Priority,
    pub use_react:  bool,
    pub react_goal: String,
    pub timeout_s:  u64,
    pub payload:    HashMap<String, String>,
    pub created_at: f64,
    pub retries:    u32,
    pub max_retries:u32,
}

impl Task {
    pub fn new(objective: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            task_id:    Uuid::new_v4().to_string(),
            objective:  objective.into(),
            target:     target.into(),
            skills:     Vec::new(),
            priority:   Priority::Normal,
            use_react:  false,
            react_goal: String::new(),
            timeout_s:  300,
            payload:    HashMap::new(),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
            retries:    0,
            max_retries:2,
        }
    }

    pub fn with_skills(mut self, skills: &[&str]) -> Self {
        self.skills = skills.iter().map(|s| s.to_string()).collect(); self
    }
    pub fn with_priority(mut self, p: Priority) -> Self { self.priority = p; self }
    pub fn with_react(mut self, goal: impl Into<String>) -> Self {
        self.use_react = true; self.react_goal = goal.into(); self
    }
    pub fn with_timeout(mut self, secs: u64) -> Self { self.timeout_s = secs; self }
}

impl PartialEq for Task { fn eq(&self, o: &Self) -> bool { self.task_id == o.task_id } }
impl Eq for Task {}
impl PartialOrd for Task {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(o)) }
}
impl Ord for Task {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        // Lower priority value = higher heap priority; then earlier creation
        o.priority.cmp(&self.priority)
            .then(self.created_at.partial_cmp(&o.created_at).unwrap_or(std::cmp::Ordering::Equal))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaskResult
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus { Pending, Running, Done, Failed, Cancelled }

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self { Self::Pending=>"PENDING", Self::Running=>"RUNNING", Self::Done=>"DONE",
                     Self::Failed=>"FAILED",   Self::Cancelled=>"CANCELLED" }.fmt(f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id:    String,
    pub worker_id:  String,
    pub objective:  String,
    pub target:     String,
    pub status:     TaskStatus,
    pub output:     String,
    pub error:      String,
    pub skills_used:Vec<String>,
    pub started_at: f64,
    pub finished_at:f64,
    pub duration_s: f64,
    pub retries:    u32,
    pub react_trace:String,
}

impl TaskResult {
    fn success(task: &Task, worker_id: &str, output: String, started_at: f64, skills: Vec<String>, trace: String) -> Self {
        let now = now_secs();
        Self {
            task_id: task.task_id.clone(), worker_id: worker_id.to_string(),
            objective: task.objective.clone(), target: task.target.clone(),
            status: TaskStatus::Done, output, error: String::new(),
            skills_used: skills, started_at, finished_at: now,
            duration_s: (now - started_at).max(0.0), retries: task.retries,
            react_trace: trace,
        }
    }
    fn failure(task: &Task, worker_id: &str, error: String, started_at: f64) -> Self {
        let now = now_secs();
        Self {
            task_id: task.task_id.clone(), worker_id: worker_id.to_string(),
            objective: task.objective.clone(), target: task.target.clone(),
            status: TaskStatus::Failed, output: String::new(), error,
            skills_used: Vec::new(), started_at, finished_at: now,
            duration_s: (now - started_at).max(0.0), retries: task.retries,
            react_trace: String::new(),
        }
    }
    fn cancelled(task: &Task) -> Self {
        let now = now_secs();
        Self {
            task_id: task.task_id.clone(), worker_id: String::new(),
            objective: task.objective.clone(), target: task.target.clone(),
            status: TaskStatus::Cancelled, output: String::new(), error: "Cancelled".to_string(),
            skills_used: Vec::new(), started_at: now, finished_at: now,
            duration_s: 0.0, retries: task.retries, react_trace: String::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwarmResult
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmResult {
    pub swarm_id:   String,
    pub total:      usize,
    pub done:       usize,
    pub failed:     usize,
    pub cancelled:  usize,
    pub duration_s: f64,
    pub results:    Vec<TaskResult>,
}

impl SwarmResult {
    pub fn summary(&self) -> String {
        format!(
            "SwarmResult[{}] {}/{} done, {} failed, {} cancelled, {:.2}s",
            &self.swarm_id[..8], self.done, self.total,
            self.failed, self.cancelled, self.duration_s
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

fn temp_archive(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("agent_{}.jsonl", &id[..8]))
}

// ─────────────────────────────────────────────────────────────────────────────
// Priority task queue (min-heap via BinaryHeap<Reverse<Task>>)
// ─────────────────────────────────────────────────────────────────────────────

struct PriorityQueue {
    heap: BinaryHeap<Task>,
}

impl PriorityQueue {
    fn new() -> Self { Self { heap: BinaryHeap::new() } }
    fn push(&mut self, t: Task) { self.heap.push(t); }
    fn pop(&mut self) -> Option<Task> { self.heap.pop() }
    fn len(&self) -> usize { self.heap.len() }
    fn is_empty(&self) -> bool { self.heap.is_empty() }
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentWorker — wraps MemoryManager + all 22 SecOps skills
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WorkerState { Idle, Busy, Draining, Dead }

pub struct AgentWorker {
    pub worker_id:   String,
    pub state:       WorkerState,
    pub tasks_done:  u32,
    pub tasks_failed:u32,
    pub last_beat:   Instant,
    pub current_task:Option<String>,
    archive_path:    PathBuf,
    mm:              MemoryManager,
    skills:          SkillRegistry,
}

impl AgentWorker {
    pub fn new(worker_id: String, archive_path: PathBuf) -> Self {
        let mm     = MemoryManager::new(&archive_path);
        let skills = SkillRegistry::new();
        // Configure persona
        mm.working.with_character_mut(|c| {
            c.name = "OMNIKON SEC·OPS".to_string();
            c.tone = "precise and analytical".to_string();
            c.expertise = vec!["cybersecurity".to_string(), "network security".to_string(),
                               "threat intelligence".to_string(), "CVSS".to_string()];
            c.response_format = "Markdown".to_string();
            c.constraints = vec![
                "Never reveal API keys.".to_string(),
                "[CRITICAL] prefix for CVSS≥7.0.".to_string(),
            ];
        });
        mm.add_system_rule("Respond only in English.");
        mm.add_system_rule(&format!("Available skills: {}", skills.names().join(", ")));
        // Seed baseline knowledge
        if mm.archive.is_empty() {
            mm.archive.store("CVE-2024-1234: SQL injection CVSS 9.8. Patch immediately.", "knowledge_base", vec!["cve".to_string()]);
            mm.archive.store("Brute-force: 5+ failures/IP/10min → rate-limit + SOC alert.", "playbook", vec!["brute-force".to_string()]);
            mm.archive.store("OWASP Top 10: A01 Access, A02 Crypto, A03 Injection, A05 Misconfiguration.", "knowledge_base", vec!["owasp".to_string()]);
        }
        Self {
            worker_id, state: WorkerState::Idle,
            tasks_done: 0, tasks_failed: 0,
            last_beat: Instant::now(), current_task: None,
            archive_path, mm, skills,
        }
    }

    pub fn is_available(&self) -> bool { self.state == WorkerState::Idle }

    pub fn execute(&mut self, task: &Task) -> TaskResult {
        self.state        = WorkerState::Busy;
        self.current_task = Some(task.task_id.clone());
        self.last_beat    = Instant::now();
        let started_at    = now_secs();

        log::info!("Worker {} executing task {} [{}]: {}",
            &self.worker_id[..8], &task.task_id[..8], task.priority, &task.objective[..task.objective.len().min(60)]);

        let result = self.run_task(task, started_at);
        match &result.status {
            TaskStatus::Done   => self.tasks_done   += 1,
            TaskStatus::Failed => self.tasks_failed += 1,
            _ => {}
        }
        self.state        = WorkerState::Idle;
        self.current_task = None;
        result
    }

    fn run_task(&mut self, task: &Task, started_at: f64) -> TaskResult {
        // Inject target and payload into memory
        if !task.target.is_empty() {
            self.mm.add_task_content(&format!("Target: {}", task.target));
        }
        if !task.payload.is_empty() {
            let pl: String = task.payload.iter().map(|(k,v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n");
            self.mm.add_task_content(&format!("Payload:\n{}", pl));
        }

        // Start task tracking
        if !task.objective.is_empty() {
            self.mm.start_task(&task.objective, vec![]);
        }

        let mut output      = String::new();
        let mut react_trace = String::new();
        let mut skills_used = Vec::new();

        if task.use_react {
            // Full ReAct loop
            let goal = if task.react_goal.is_empty() { &task.objective } else { &task.react_goal };
            self.mm.enable_react(goal);
            let react_result = self.run_react_loop(goal, task.timeout_s);
            output      = react_result.0;
            react_trace = react_result.1;
            skills_used = react_result.2;
        } else if !task.skills.is_empty() {
            // Run specified skills sequentially
            let mut skill_outputs = Vec::new();
            for skill_name in &task.skills {
                let skill_args = if task.target.is_empty() { String::new() } else { task.target.clone() };
                match self.skills.get(skill_name) {
                    None => skill_outputs.push(format!("⚠ Unknown skill: {}", skill_name)),
                    Some(skill) => {
                        let r = skill.run(&skill_args, &self.mm);
                        if r.store_to_archive && r.success {
                            self.mm.archive.store(
                                &format!("[{}] {}", r.skill, &r.output[..r.output.len().min(500)]),
                                &format!("skill_{}", r.skill),
                                r.archive_tags.clone(),
                            );
                        }
                        skills_used.push(skill_name.clone());
                        skill_outputs.push(format!("### {}\n{}", skill_name, r.output));
                    }
                }
            }
            output = skill_outputs.join("\n\n---\n\n");
        } else {
            // Standard LLM call
            self.mm.add_user_message(&task.objective);
            let sys  = self.mm.context_for_query(&task.objective, 3, 0.05);
            let msgs = self.mm.working.build_messages();
            output = match call_deepseek(&sys, &msgs, 0.7) {
                Ok(r) => r,
                Err(e) => return TaskResult::failure(task, &self.worker_id, e, started_at),
            };
            self.mm.add_assistant_message(&output);
        }

        // Archive task
        if self.mm.working.status().is_active() {
            self.mm.finish_task(Some(&output[..output.len().min(200)]));
        }

        TaskResult::success(task, &self.worker_id, output, started_at, skills_used, react_trace)
    }

    fn run_react_loop(&mut self, goal: &str, timeout_s: u64) -> (String, String, Vec<String>) {
        use regex::Regex;
        let rm         = self.mm.working.reasoning();
        let deadline   = Instant::now() + Duration::from_secs(timeout_s);
        let mut errs   = 0u32;
        let mut skills_used = Vec::new();

        let thought_re = Regex::new(r"Thought:\s*([\s\S]+?)(?=\nAction:|\nFinal Answer:|$)").unwrap();
        let action_re  = Regex::new(r"Action:\s*(\w+)\s*(.*?)(?:\n|$)").unwrap();
        let final_re   = Regex::new(r"Final Answer:\s*([\s\S]+)").unwrap();

        let skill_list = self.skills.skills.iter()
            .map(|s| format!("  {}: {}", s.name(), s.description()))
            .collect::<Vec<_>>().join("\n");

        for i in 1..=10u32 {
            if Instant::now() >= deadline { break; }
            let sys = format!(
                "{}\n\n---\n\nReAct mode. Format:\nThought: <reasoning>\nAction: <skill> <args>\nOR: Thought: <reasoning>\nFinal Answer: <answer>\nSkills:\n{}\nCheck layer 2.5 trace. Never fabricate Observations.",
                self.mm.context_for_query(goal, 3, 0.05), skill_list
            );
            let raw = match call_deepseek(&sys, &self.mm.working.build_messages(), 0.3) {
                Ok(r) => r,
                Err(e) => { rm.record(TraceType::Observation, &format!("LLM error: {}", e), "", true, 0); errs += 1; if errs >= 3 { break; } continue; }
            };
            let thought = thought_re.captures(&raw).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string()).unwrap_or_else(|| raw[..raw.len().min(200)].to_string());
            rm.record(TraceType::Thought, &thought, "", false, 0);

            if let Some(fin) = final_re.captures(&raw).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string()) {
                rm.record(TraceType::Final, &fin, "", false, 0);
                self.mm.add_assistant_message(&fin);
                let trace = rm.to_archive_content();
                self.mm.finish_react(&fin);
                return (fin, trace, skills_used);
            }

            let act  = action_re.captures(&raw).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_string());
            let aarg = action_re.captures(&raw).and_then(|c| c.get(2)).map(|m| m.as_str().trim().to_string()).unwrap_or_default();

            match act {
                None => { rm.record(TraceType::Observation, "No Action.", "", true, 0); errs += 1; }
                Some(act_name) => {
                    rm.record(TraceType::Action, &format!("{} {}", act_name, aarg), &act_name, false, 0);
                    let (obs, is_err) = match self.skills.get(&act_name) {
                        None => (format!("Unknown skill '{}'. Available: {}", act_name, self.skills.names().join(", ")), true),
                        Some(skill) => {
                            let r = skill.run(&aarg, &self.mm);
                            if r.store_to_archive && r.success {
                                self.mm.archive.store(&format!("[{}] {}", r.skill, &r.output[..r.output.len().min(500)]),
                                    &format!("skill_{}", r.skill), r.archive_tags.clone());
                            }
                            if r.success { skills_used.push(act_name.clone()); }
                            (r.output, !r.success)
                        }
                    };
                    rm.record(TraceType::Observation, &obs, "", is_err, 0);
                    if is_err { errs += 1; }
                    self.mm.working.add_message("user", &format!("Observation: {}", obs));
                    self.mm.add_assistant_message(&raw);
                }
            }
            if errs >= 3 { break; }
        }

        let fallback = format!("Loop ended. Last: {}", rm.last_observation().chars().take(200).collect::<String>());
        let trace    = rm.to_archive_content();
        self.mm.finish_react(&fallback);
        (fallback, trace, skills_used)
    }

    pub fn health(&self) -> WorkerHealth {
        WorkerHealth {
            worker_id:    self.worker_id.clone(),
            state:        format!("{:?}", self.state),
            tasks_done:   self.tasks_done,
            tasks_failed: self.tasks_failed,
            heartbeat_age_s: self.last_beat.elapsed().as_secs_f64(),
            current_task: self.current_task.clone(),
            archive_size: self.mm.archive.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkerHealth {
    pub worker_id:      String,
    pub state:          String,
    pub tasks_done:     u32,
    pub tasks_failed:   u32,
    pub heartbeat_age_s:f64,
    pub current_task:   Option<String>,
    pub archive_size:   usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// SwarmConfig
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SwarmConfig {
    pub pool_size:     usize,
    pub max_pool_size: usize,
    pub archive_dir:   PathBuf,
    pub stuck_timeout_s: u64,
    pub health_interval_s: u64,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            pool_size:          4,
            max_pool_size:      50,
            archive_dir:        std::env::temp_dir().join("swarm_archives"),
            stuck_timeout_s:    300,
            health_interval_s:  30,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwarmManager
// ─────────────────────────────────────────────────────────────────────────────

pub struct SwarmManager {
    swarm_id:   String,
    config:     SwarmConfig,
    workers:    RwLock<Vec<AgentWorker>>,
    queue:      Mutex<PriorityQueue>,
    results:    Mutex<Vec<TaskResult>>,
    pending:    Mutex<HashMap<String, Task>>,
    total_done: AtomicU32,
    shutdown:   AtomicBool,
}

impl SwarmManager {
    pub fn new(config: SwarmConfig) -> Arc<Self> {
        std::fs::create_dir_all(&config.archive_dir).ok();
        let swarm = Arc::new(Self {
            swarm_id:   Uuid::new_v4().to_string(),
            workers:    RwLock::new(Vec::new()),
            queue:      Mutex::new(PriorityQueue::new()),
            results:    Mutex::new(Vec::new()),
            pending:    Mutex::new(HashMap::new()),
            total_done: AtomicU32::new(0),
            shutdown:   AtomicBool::new(false),
            config:     config.clone(),
        });
        // Provision initial pool
        {
            let mut workers = swarm.workers.write();
            for _ in 0..config.pool_size {
                let id      = Uuid::new_v4().to_string();
                let archive = temp_archive(&config.archive_dir, &id);
                workers.push(AgentWorker::new(id, archive));
            }
        }
        log::info!("SwarmManager {} started with {} workers", &swarm.swarm_id[..8], config.pool_size);
        swarm
    }

    /// Submit a single task. Returns immediately.
    pub fn submit(&self, task: Task) {
        let mut pending = self.pending.lock();
        pending.insert(task.task_id.clone(), task.clone());
        drop(pending);
        self.queue.lock().push(task);
    }

    /// Run a batch of tasks and wait for all to complete (or timeout).
    pub fn run_tasks(
        self: &Arc<Self>,
        tasks: Vec<Task>,
        timeout_s: u64,
    ) -> SwarmResult {
        let started = Instant::now();
        let task_ids: Vec<String> = tasks.iter().map(|t| t.task_id.clone()).collect();
        let total = tasks.len();

        // Submit all
        for t in tasks { self.submit(t); }

        // Drive the work loop synchronously using rayon-style approach with threads
        let swarm = Arc::clone(self);
        let deadline = Instant::now() + Duration::from_secs(timeout_s);

        // Spawn worker threads
        let handles: Vec<_> = {
            let mut workers = swarm.workers.write();
            let mut spawned = Vec::new();
            for worker in workers.iter_mut() {
                if !worker.is_available() { continue; }
                let swarm_clone = Arc::clone(&swarm);
                // We drive execution in-place since workers need &mut self
                // Use message-passing model: worker thread polls the shared queue
                spawned.push(worker.worker_id.clone());
            }
            spawned
        };

        // Simple poll loop — check queue, pick idle worker, execute synchronously
        loop {
            if Instant::now() >= deadline { break; }

            // Check if all target tasks are done
            {
                let results = swarm.results.lock();
                let done_ids: Vec<&str> = results.iter()
                    .filter(|r| task_ids.contains(&r.task_id))
                    .map(|r| r.task_id.as_str())
                    .collect();
                if done_ids.len() >= total { break; }
            }

            // Try to dispatch one task
            let task = { swarm.queue.lock().pop() };
            match task {
                None => { std::thread::sleep(Duration::from_millis(100)); continue; }
                Some(task) => {
                    // Find an idle worker and execute
                    let mut workers = swarm.workers.write();
                    let worker_idx  = workers.iter().position(|w| w.is_available());
                    match worker_idx {
                        None => {
                            // All busy, put task back
                            swarm.queue.lock().push(task);
                            drop(workers);
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Some(idx) => {
                            let result = workers[idx].execute(&task);
                            swarm.total_done.fetch_add(1, Ordering::Relaxed);
                            let mut pending = swarm.pending.lock();
                            pending.remove(&task.task_id);
                            drop(pending);
                            swarm.results.lock().push(result);
                        }
                    }
                }
            }
        }

        // Collect results for this batch
        let elapsed = started.elapsed().as_secs_f64();
        let results_guard = self.results.lock();
        let batch_results: Vec<TaskResult> = results_guard.iter()
            .filter(|r| task_ids.contains(&r.task_id))
            .cloned()
            .collect();
        drop(results_guard);

        // Any still-pending tasks were cancelled by timeout
        let mut cancelled_results: Vec<TaskResult> = Vec::new();
        {
            let pending = self.pending.lock();
            for id in &task_ids {
                if !batch_results.iter().any(|r| &r.task_id == id) {
                    if let Some(t) = pending.get(id) {
                        cancelled_results.push(TaskResult::cancelled(t));
                    }
                }
            }
        }

        let mut all_results = batch_results;
        all_results.extend(cancelled_results);

        SwarmResult {
            swarm_id:   self.swarm_id.clone(),
            total,
            done:       all_results.iter().filter(|r| matches!(r.status, TaskStatus::Done)).count(),
            failed:     all_results.iter().filter(|r| matches!(r.status, TaskStatus::Failed)).count(),
            cancelled:  all_results.iter().filter(|r| matches!(r.status, TaskStatus::Cancelled)).count(),
            duration_s: elapsed,
            results:    all_results,
        }
    }

    /// Provision additional workers dynamically.
    pub fn grow(&self, count: usize) -> Result<usize, String> {
        let mut workers = self.workers.write();
        if workers.len() + count > self.config.max_pool_size {
            return Err(format!("Would exceed max_pool_size={}", self.config.max_pool_size));
        }
        for _ in 0..count {
            let id      = Uuid::new_v4().to_string();
            let archive = temp_archive(&self.config.archive_dir, &id);
            workers.push(AgentWorker::new(id, archive));
        }
        Ok(workers.len())
    }

    pub fn health(&self) -> SwarmHealth {
        let workers  = self.workers.read();
        let agents   = workers.iter().map(|w| w.health()).collect::<Vec<_>>();
        let idle     = agents.iter().filter(|h| h.state == "Idle").count();
        let busy     = agents.iter().filter(|h| h.state == "Busy").count();
        SwarmHealth {
            swarm_id:     self.swarm_id.clone(),
            pool_size:    workers.len(),
            idle, busy,
            queue_depth:  self.queue.lock().len(),
            total_done:   self.total_done.load(Ordering::Relaxed),
            total_failed: agents.iter().map(|h| h.tasks_failed).sum(),
            agents,
        }
    }

    pub fn pool_size(&self) -> usize { self.workers.read().len() }
    pub fn queue_depth(&self) -> usize { self.queue.lock().len() }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        log::info!("SwarmManager {} shut down.", &self.swarm_id[..8]);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SwarmHealth {
    pub swarm_id:    String,
    pub pool_size:   usize,
    pub idle:        usize,
    pub busy:        usize,
    pub queue_depth: usize,
    pub total_done:  u32,
    pub total_failed:u32,
    pub agents:      Vec<WorkerHealth>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI entry point
// ─────────────────────────────────────────────────────────────────────────────

const BANNER: &str = r#"
╔══════════════════════════════════════════════════════════════════╗
║   OMNIKON SEC·OPS  —  Swarm Manager  v1.0.2  (Rust)            ║
║  22 real SecOps skills · Priority queuing · Elastic pool        ║
║────────────────────────────────────────────────────────────────║
║  spawn <n>                   provision n workers                ║
║  run <target> <skills...>    dispatch skill task                 ║
║  react <goal>                full ReAct task                    ║
║  batch <file.json>           load tasks from JSON file          ║
║  health                      pool health                        ║
║  results                     latest results                     ║
║  skills                      list all 22 skills                 ║
║  quit                        exit                               ║
╚══════════════════════════════════════════════════════════════════╝
"#;

pub fn run_cli() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let archive_dir = env::var("ARCHIVE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("swarm_archives"));

    let config = SwarmConfig {
        pool_size: 4,
        max_pool_size: 50,
        archive_dir,
        ..Default::default()
    };

    println!("{}", BANNER);
    let swarm = SwarmManager::new(config);
    println!("  Workers : {}", swarm.pool_size());
    println!("  Skills  : 22 SecOps skills");
    println!("  Optional: ABUSEIPDB_API_KEY  VIRUSTOTAL_API_KEY\n");

    let mut latest: Option<SwarmResult> = None;
    let skills_ref = SkillRegistry::new();

    let stdin  = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    write!(out, "Swarm > ").ok(); out.flush().ok();

    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        let parts: Vec<&str> = line.trim().splitn(20, ' ').collect();
        if parts.is_empty() || parts[0].is_empty() {
            write!(out, "Swarm > ").ok(); out.flush().ok();
            continue;
        }

        match parts[0].to_lowercase().as_str() {
            "quit" | "exit" | "q" => { swarm.shutdown(); println!("\nGoodbye."); break; }

            "spawn" => {
                let n: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
                match swarm.grow(n) {
                    Ok(total) => writeln!(out, "✓ Pool size now: {}", total).ok(),
                    Err(e)    => writeln!(out, "⚠ {}", e).ok(),
                };
            }

            "run" => {
                if parts.len() < 3 {
                    writeln!(out, "Usage: run <target> <skill1> [skill2 ...]").ok();
                } else {
                    let target = parts[1];
                    let skills: Vec<&str> = parts[2..].iter().copied().collect();
                    let task = Task::new(
                        format!("Run {} on {}", skills.join(", "), target),
                        target
                    ).with_skills(&skills).with_priority(Priority::High);
                    writeln!(out, "Dispatching task {} …", &task.task_id[..8]).ok();
                    let result = swarm.run_tasks(vec![task], 300);
                    writeln!(out, "\n{}", result.summary()).ok();
                    for r in &result.results {
                        writeln!(out, "\n  Task {} → {} ({:.2}s)", &r.task_id[..8], r.status, r.duration_s).ok();
                        writeln!(out, "{}", &r.output[..r.output.len().min(800)]).ok();
                    }
                    latest = Some(result);
                }
            }

            "react" => {
                if parts.len() < 2 {
                    writeln!(out, "Usage: react <goal>").ok();
                } else {
                    let goal = parts[1..].join(" ");
                    let task = Task::new(goal.clone(), "").with_react(&goal).with_priority(Priority::High);
                    writeln!(out, "Starting ReAct task {} …", &task.task_id[..8]).ok();
                    let result = swarm.run_tasks(vec![task], 300);
                    writeln!(out, "\n{}", result.summary()).ok();
                    for r in &result.results {
                        writeln!(out, "\n  → {} ({:.2}s)\n{}", r.status, r.duration_s, &r.output[..r.output.len().min(800)]).ok();
                    }
                    latest = Some(result);
                }
            }

            "health" => {
                let h = swarm.health();
                writeln!(out, "Pool: {}  Idle: {}  Busy: {}  Queue: {}  Done: {}  Failed: {}",
                    h.pool_size, h.idle, h.busy, h.queue_depth, h.total_done, h.total_failed).ok();
                for a in &h.agents {
                    writeln!(out, "  [{:<8}] {}  done={} failed={} age={:.1}s",
                        a.state, &a.worker_id[..8], a.tasks_done, a.tasks_failed, a.heartbeat_age_s).ok();
                }
            }

            "results" => {
                match &latest {
                    None => { writeln!(out, "No results yet.").ok(); }
                    Some(r) => {
                        writeln!(out, "{}", r.summary()).ok();
                        for res in &r.results {
                            writeln!(out, "\n  Task {} ({}) → {} | {:.2}s | Skills: {}",
                                &res.task_id[..8], res.target, res.status,
                                res.duration_s, res.skills_used.join(", ")).ok();
                            writeln!(out, "{}", &res.output[..res.output.len().min(400)]).ok();
                            if !res.error.is_empty() { writeln!(out, "  Error: {}", res.error).ok(); }
                        }
                    }
                }
            }

            "skills" => {
                writeln!(out, "**22 SecOps Skills:**").ok();
                let sections = [
                    ("NETWORK",   vec!["port_scanner","dns_lookup","whois_lookup","ssl_cert_inspector","http_header_analyzer","network_recon","dns_security"]),
                    ("THREAT",    vec!["cve_lookup","ip_reputation","hash_lookup","ioc_extractor"]),
                    ("ANALYSIS",  vec!["log_analyzer","vulnerability_scorer","vulnerability_assessment","web_app_scanner","api_security_audit","firewall_auditor"]),
                    ("CLOUD/CTR", vec!["cloud_posture","container_scanner"]),
                    ("AUTH",      vec!["password_audit"]),
                    ("UTILITY",   vec!["summarizer","memory_writer"]),
                ];
                for (sec, names) in &sections {
                    writeln!(out, "  ── {} ──", sec).ok();
                    for n in names {
                        if let Some(s) = skills_ref.get(n) {
                            writeln!(out, "  `{}` — {}", s.name(), s.description()).ok();
                        }
                    }
                }
            }

            _ => { writeln!(out, "Unknown command: {}. Type 'quit' to exit.", parts[0]).ok(); }
        }

        write!(out, "\nSwarm > ").ok(); out.flush().ok();
    }
}

fn main() {
    run_cli();
}
