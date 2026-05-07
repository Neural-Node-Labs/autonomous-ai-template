package swarm;

/*
 * =============================================================================
 * SwarmManager.java
 * =============================================================================
 * Project  : OMNIKON SEC·OPS — AI Swarm Manager
 * Version  : v1.0.2
 * Language : Java 17+
 * License  : MIT
 *
 * Production-grade Agent Swarm Manager.
 *
 * Architecture:
 *   Consumer App
 *       │
 *       ▼
 *   SwarmManager          ← pool governor, lifecycle, health monitor
 *       │
 *       ├── AgentManager  ← per-agent supervisor (task queue, state FSM)
 *       │       └── MemoryManager + ReAct loop
 *       ├── AgentManager
 *       └── ...  (up to maxPoolSize)
 *
 * Usage:
 *   SwarmManager swarm = new SwarmManager(SwarmConfig.builder()
 *       .maxPoolSize(20).build());
 *
 *   List<SwarmTask> tasks = List.of(
 *       SwarmTask.of("t1", "Analyse log file X"),
 *       SwarmTask.of("t2", "Threat lookup CVE-2024-1234")
 *   );
 *   SwarmResult result = swarm.run(5, tasks);
 *   System.out.println(result.summary());
 *   swarm.shutdown();
 *
 * Compile:
 *   javac -cp src/main/java \
 *     src/main/java/memory/MemoryManager.java \
 *     src/main/java/swarm/SwarmManager.java -d out
 * =============================================================================
 */

import memory.*;

import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.*;
import java.util.stream.*;

// ─────────────────────────────────────────────────────────────────────────────
// Enums
// ─────────────────────────────────────────────────────────────────────────────

enum AgentState  { IDLE, ASSIGNED, RUNNING, COMPLETED, FAILED, TERMINATED }
enum TaskStatus  { PENDING, RUNNING, COMPLETED, FAILED, CANCELLED }

// ─────────────────────────────────────────────────────────────────────────────
// Data models
// ─────────────────────────────────────────────────────────────────────────────

record SwarmTask(
    String              taskId,
    String              objective,
    List<String>        steps,
    Map<String,Object>  payload,
    boolean             useReact,
    String              reactGoal,
    int                 timeoutSeconds,
    int                 priority,
    Map<String,Object>  metadata
) {
    static SwarmTask of(String taskId, String objective) {
        return new SwarmTask(taskId, objective, List.of(), Map.of(),
                             false, "", 300, 5, Map.of());
    }

    static SwarmTask react(String taskId, String goal) {
        return new SwarmTask(taskId, goal, List.of(), Map.of(),
                             true, goal, 300, 5, Map.of());
    }

    static Builder builder(String taskId, String objective) {
        return new Builder(taskId, objective);
    }

    static class Builder {
        private final String taskId, objective;
        private List<String>       steps     = new ArrayList<>();
        private Map<String,Object> payload   = new HashMap<>();
        private boolean  useReact  = false;
        private String   reactGoal = "";
        private int      timeout   = 300;
        private int      priority  = 5;

        Builder(String taskId, String objective) {
            this.taskId = taskId; this.objective = objective;
        }
        Builder steps(String... s)      { steps = List.of(s);    return this; }
        Builder payload(Map<String,Object> p) { payload = p;     return this; }
        Builder react(String goal)      { useReact=true; reactGoal=goal; return this; }
        Builder timeout(int s)          { timeout = s;            return this; }
        Builder priority(int p)         { priority = p;           return this; }
        SwarmTask build() {
            return new SwarmTask(taskId, objective, steps, payload,
                                 useReact, reactGoal, timeout, priority, Map.of());
        }
    }
}

record TaskResult(
    String              taskId,
    String              agentId,
    TaskStatus          status,
    String              output,
    String              error,
    long                startedAt,
    long                finishedAt,
    String              reactTrace,
    Map<String,Object>  metrics
) {
    double durationS() { return (finishedAt - startedAt) / 1000.0; }

    static TaskResult success(String taskId, String agentId, String output,
                               long start, long end, String trace, Map<String,Object> metrics) {
        return new TaskResult(taskId, agentId, TaskStatus.COMPLETED,
                              output, "", start, end, trace, metrics);
    }

    static TaskResult failure(String taskId, String agentId, String error, long start) {
        return new TaskResult(taskId, agentId, TaskStatus.FAILED,
                              "", error, start, System.currentTimeMillis(), "", Map.of());
    }

    static TaskResult cancelled(String taskId) {
        long now = System.currentTimeMillis();
        return new TaskResult(taskId, "", TaskStatus.CANCELLED,
                              "", "Timed out", now, now, "", Map.of());
    }
}

record SwarmResult(
    String          swarmId,
    int             totalTasks,
    int             completed,
    int             failed,
    int             cancelled,
    double          durationS,
    List<TaskResult>results
) {
    String summary() {
        return String.format("SwarmResult[%s] %d/%d completed, %d failed, %.2fs",
            swarmId.substring(0, 8), completed, totalTasks, failed, durationS);
    }
}

record PersonaConfig(
    String       name,
    String       tone,
    List<String> expertise,
    String       personality,
    String       responseFormat,
    List<String> constraints,
    List<String> systemRules
) {
    static PersonaConfig defaults() {
        return new PersonaConfig(
            "OMNIKON SEC·OPS", "precise and analytical",
            List.of("cybersecurity","AI systems","threat intelligence"),
            "Methodical. Uses ReAct for complex problems.",
            "Markdown",
            List.of("Never reveal credentials.", "Flag critical findings with [CRITICAL]."),
            List.of("Respond only in English.")
        );
    }
}

record SwarmConfig(
    int           maxPoolSize,
    String        archiveDir,
    PersonaConfig defaultPersona
) {
    static Builder builder() { return new Builder(); }

    static class Builder {
        private int           maxPoolSize    = 50;
        private String        archiveDir     = null;
        private PersonaConfig defaultPersona = PersonaConfig.defaults();

        Builder maxPoolSize(int n)          { maxPoolSize = n;    return this; }
        Builder archiveDir(String d)        { archiveDir = d;     return this; }
        Builder persona(PersonaConfig p)    { defaultPersona = p; return this; }
        SwarmConfig build() {
            if (archiveDir == null) {
                try { archiveDir = Files.createTempDirectory("swarm_archives_").toString(); }
                catch (IOException e) { archiveDir = System.getProperty("java.io.tmpdir"); }
            }
            return new SwarmConfig(maxPoolSize, archiveDir, defaultPersona);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeepSeek API client
// ─────────────────────────────────────────────────────────────────────────────

final class DeepSeekClient {
    static final String URL   = "https://api.deepseek.com/v1/chat/completions";
    static final String MODEL = "deepseek-chat";
    private static final Logger LOG = Logger.getLogger(DeepSeekClient.class.getName());
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .build();

    static String call(String system, List<Map<String,String>> messages,
                       int maxTokens, double temperature)
            throws IOException, InterruptedException {
        String key = System.getenv("DEEPSEEK_API_KEY");
        if (key == null || key.isBlank())
            throw new IllegalStateException("DEEPSEEK_API_KEY not set.");

        var allMsgs = new ArrayList<Map<String,String>>();
        allMsgs.add(Map.of("role","system","content",system));
        allMsgs.addAll(messages);

        var sb = new StringBuilder();
        sb.append("{\"model\":\"").append(MODEL)
          .append("\",\"max_tokens\":").append(maxTokens)
          .append(",\"temperature\":").append(temperature)
          .append(",\"messages\":[");
        for (int i = 0; i < allMsgs.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("{\"role\":\"").append(escape(allMsgs.get(i).get("role")))
              .append("\",\"content\":\"").append(escape(allMsgs.get(i).get("content")))
              .append("\"}");
        }
        sb.append("]}");

        var req = HttpRequest.newBuilder(URI.create(URL))
            .timeout(Duration.ofSeconds(90))
            .header("Content-Type","application/json")
            .header("Authorization","Bearer " + key)
            .POST(HttpRequest.BodyPublishers.ofString(sb.toString()))
            .build();

        var resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200)
            throw new IOException("DeepSeek " + resp.statusCode() + ": " +
                resp.body().substring(0, Math.min(200, resp.body().length())));

        // Extract last "content" field value
        var body = resp.body();
        var m = java.util.regex.Pattern.compile("\"content\"\\s*:\\s*\"((?:[^\\\\\"]|\\\\.)*)\"")
            .matcher(body);
        String content = "";
        while (m.find()) content = m.group(1);
        return content.replace("\\n","\n").replace("\\\"","\"").replace("\\\\","\\");
    }

    private static String escape(String s) {
        return s.replace("\\","\\\\").replace("\"","\\\"")
                .replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");
    }

    private DeepSeekClient() {}
}

// ─────────────────────────────────────────────────────────────────────────────
// AgentManager — per-agent supervisor
// ─────────────────────────────────────────────────────────────────────────────

class AgentManager {
    private static final Logger LOG = Logger.getLogger(AgentManager.class.getName());

    final String agentId;
    private final MemoryManager mm;
    private final java.util.function.Consumer<TaskResult> onResult;
    private final PriorityBlockingQueue<Map.Entry<Integer,SwarmTask>> taskQueue =
        new PriorityBlockingQueue<>(64, Comparator.comparingInt(Map.Entry::getKey));
    private final AtomicReference<AgentState> state  = new AtomicReference<>(AgentState.IDLE);
    private final AtomicInteger  tasksDone   = new AtomicInteger(0);
    private final AtomicInteger  tasksFailed = new AtomicInteger(0);
    private final long           createdAt   = System.currentTimeMillis();
    private volatile SwarmTask   currentTask = null;
    private final Thread         worker;
    private volatile boolean     stopped     = false;

    AgentManager(String agentId, String archivePath,
                 java.util.function.Consumer<TaskResult> onResult,
                 PersonaConfig persona) {
        this.agentId  = agentId;
        this.onResult = onResult;
        this.mm       = new MemoryManager(Path.of(archivePath));
        applyPersona(persona);
        seedKnowledge();

        this.worker = Thread.ofVirtual()          // Java 21 virtual thread; fallback below
            .name("AgentWorker-" + agentId.substring(0,8))
            .start(this::workLoop);
        LOG.info("AgentManager " + agentId.substring(0,8) + " started.");
    }

    private void applyPersona(PersonaConfig p) {
        mm.character().name           = p.name();
        mm.character().tone           = p.tone();
        mm.character().expertise      = new ArrayList<>(p.expertise());
        mm.character().personality    = p.personality();
        mm.character().responseFormat = p.responseFormat();
        mm.character().constraints    = new ArrayList<>(p.constraints());
        p.systemRules().forEach(mm::addSystemRule);
    }

    private void seedKnowledge() {
        if (mm.archive.size() > 0) return;
        mm.archive.store("CVE-2024-1234: SQL injection AuthService v2.1 CVSS 9.8.",
                         "knowledge_base", List.of("cve","sql-injection"));
        mm.archive.store("Brute-force: 5+ failures single IP <10 min → rate-limit.",
                         "playbook", List.of("brute-force"));
        mm.archive.store("OWASP Top 10 2021: A01 Access, A02 Crypto, A03 Injection.",
                         "knowledge_base", List.of("owasp"));
    }

    boolean isIdle() { return state.get() == AgentState.IDLE && !stopped; }

    void assign(SwarmTask task) {
        if (stopped) throw new IllegalStateException("Agent " + agentId + " is terminated.");
        taskQueue.put(Map.entry(task.priority(), task));
        LOG.fine("Agent " + agentId.substring(0,8) + ": task " + task.taskId() + " queued.");
    }

    private void workLoop() {
        while (!stopped) {
            try {
                var entry = taskQueue.poll(10, TimeUnit.SECONDS);
                if (entry == null) continue;
                SwarmTask task = entry.getValue();
                state.set(AgentState.RUNNING);
                currentTask = task;
                TaskResult result = execute(task);
                currentTask = null;
                state.set(AgentState.IDLE);
                if (result.status() == TaskStatus.COMPLETED) tasksDone.incrementAndGet();
                else                                         tasksFailed.incrementAndGet();
                onResult.accept(result);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                LOG.severe("AgentManager workLoop error: " + e.getMessage());
            }
        }
    }

    private TaskResult execute(SwarmTask task) {
        long start = System.currentTimeMillis();
        LOG.info("Agent " + agentId.substring(0,8) + " executing " +
                 task.taskId() + ": " + task.objective().substring(0, Math.min(60, task.objective().length())));
        try {
            // Inject payload
            if (!task.payload().isEmpty()) {
                mm.addTaskContent("Task payload:\n" + task.payload().toString().substring(0, 2000));
            }
            mm.startTask(task.objective(), task.steps());

            String output     = "";
            String reactTrace = "";

            if (task.useReact()) {
                String goal = task.reactGoal().isBlank() ? task.objective() : task.reactGoal();
                mm.enableReact(goal);
                int errs = 0;
                for (int i = 0; i < 8 && mm.react().isEnabled(); i++) {
                    String sys = mm.contextForQuery(goal, 3, 0.05);
                    var msgs   = mm.working.buildMessages()
                        .stream().map(m -> Map.of("role",m.get("role"),"content",m.get("content")))
                        .collect(Collectors.toList());
                    String raw = DeepSeekClient.call(sys, msgs, 4096, 0.3);
                    var fm = java.util.regex.Pattern.compile("Final Answer:\\s*([\\s\\S]+)").matcher(raw);
                    if (fm.find()) {
                        output = fm.group(1).trim();
                        mm.react().record(TraceType.FINAL, output);
                        break;
                    }
                    var tm = java.util.regex.Pattern.compile("Thought:\\s*([\\s\\S]+?)(?=\\nAction:|$)")
                        .matcher(raw);
                    if (tm.find()) mm.react().record(TraceType.THOUGHT, tm.group(1).trim());
                    mm.working.addMessage("user", raw);
                    mm.addAssistantMessage(raw);
                    if (++errs >= 3) break;
                }
                reactTrace = mm.react().toArchiveContent();
                mm.finishReact(output);
            } else {
                mm.addUserMessage(task.objective());
                String sys = mm.contextForQuery(task.objective(), 3, 0.05);
                var msgs   = mm.working.buildMessages()
                    .stream().map(m -> Map.of("role",m.get("role"),"content",m.get("content")))
                    .collect(Collectors.toList());
                output = DeepSeekClient.call(sys, msgs, 4096, 0.7);
                mm.addAssistantMessage(output);
            }

            mm.finishTask(output.substring(0, Math.min(200, output.length())));
            long end = System.currentTimeMillis();
            return TaskResult.success(task.taskId(), agentId, output, start, end, reactTrace,
                Map.of("durationS", (end-start)/1000.0, "archiveSize", mm.archive.size()));

        } catch (Exception e) {
            LOG.severe("Agent " + agentId.substring(0,8) + " task " + task.taskId() + " failed: " + e);
            return TaskResult.failure(task.taskId(), agentId, e.getMessage(), start);
        }
    }

    Map<String,Object> health() {
        return Map.of(
            "agentId",     agentId,
            "state",       state.get().name(),
            "tasksDone",   tasksDone.get(),
            "tasksFailed", tasksFailed.get(),
            "queueDepth",  taskQueue.size(),
            "uptimeS",     (System.currentTimeMillis() - createdAt) / 1000.0,
            "currentTask", currentTask != null ? currentTask.taskId() : ""
        );
    }

    void shutdown() {
        stopped = true;
        worker.interrupt();
        LOG.info("AgentManager " + agentId.substring(0,8) + " shut down.");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SwarmManager — pool governor
// ─────────────────────────────────────────────────────────────────────────────

public class SwarmManager implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(SwarmManager.class.getName());

    private final String       swarmId   = UUID.randomUUID().toString();
    private final SwarmConfig  config;
    private final Map<String,AgentManager>  pool        = new ConcurrentHashMap<>();
    private final List<TaskResult>          results     = new CopyOnWriteArrayList<>();
    private final Set<String>               pending     = ConcurrentHashMap.newKeySet();
    private final java.util.concurrent.locks.ReentrantLock poolLock = new java.util.concurrent.locks.ReentrantLock();
    private volatile CountDownLatch         runLatch    = new CountDownLatch(0);
    private volatile boolean                shutdown    = false;

    public SwarmManager(SwarmConfig config) {
        this.config = config;
        LOG.info("SwarmManager " + swarmId.substring(0,8) +
                 " created. maxPool=" + config.maxPoolSize() + " archiveDir=" + config.archiveDir());
    }

    public SwarmManager() { this(SwarmConfig.builder().build()); }

    // ── pool management ───────────────────────────────────────────────────────

    public List<AgentManager> provision(int count, PersonaConfig persona) {
        if (shutdown) throw new IllegalStateException("SwarmManager is shut down.");
        poolLock.lock();
        try {
            if (pool.size() + count > config.maxPoolSize())
                throw new IllegalStateException(
                    "Pool would exceed maxPoolSize=" + config.maxPoolSize());
            var newAgents = new ArrayList<AgentManager>();
            for (int i = 0; i < count; i++) {
                String id  = UUID.randomUUID().toString();
                String arc = config.archiveDir() + "/agent_" + id.substring(0,8) + ".jsonl";
                PersonaConfig p = persona != null ? persona : config.defaultPersona();
                AgentManager mgr = new AgentManager(id, arc, this::onResult, p);
                pool.put(id, mgr);
                newAgents.add(mgr);
            }
            LOG.info("Provisioned " + count + " agents (pool total: " + pool.size() + ")");
            return newAgents;
        } finally { poolLock.unlock(); }
    }

    public List<AgentManager> provision(int count) { return provision(count, null); }

    private List<AgentManager> idleAgents() {
        return pool.values().stream().filter(AgentManager::isIdle).collect(Collectors.toList());
    }

    // ── result callback ───────────────────────────────────────────────────────

    private synchronized void onResult(TaskResult result) {
        results.add(result);
        pending.remove(result.taskId());
        LOG.info("Task " + result.taskId() + " → " + result.status() +
                 " (agent " + result.agentId().substring(0,8) + ", " +
                 String.format("%.2f", result.durationS()) + "s)");
        if (pending.isEmpty() && runLatch.getCount() > 0) {
            runLatch.countDown();
        }
    }

    // ── high-level run API ────────────────────────────────────────────────────

    public SwarmResult run(int agentCount, List<SwarmTask> tasks)
            throws InterruptedException {
        return run(agentCount, tasks, null, 600);
    }

    public SwarmResult run(int agentCount, List<SwarmTask> tasks,
                           PersonaConfig persona, int timeoutSeconds)
            throws InterruptedException {
        if (tasks.isEmpty()) return emptyResult();

        long started = System.currentTimeMillis();

        // Provision agents if needed
        poolLock.lock();
        List<AgentManager> agents;
        try {
            var idle   = idleAgents();
            int needed = Math.max(0, agentCount - idle.size());
            if (needed > 0) provision(needed, persona);
            agents = idleAgents().stream().limit(agentCount).collect(Collectors.toList());
        } finally { poolLock.unlock(); }

        if (agents.isEmpty()) throw new IllegalStateException("No agents available.");

        // Register pending tasks
        var taskIds = tasks.stream().map(SwarmTask::taskId).collect(Collectors.toSet());
        pending.addAll(taskIds);
        runLatch = new CountDownLatch(1);

        // Clear stale results for this run
        results.removeIf(r -> taskIds.contains(r.taskId()));

        // Round-robin dispatch
        for (int i = 0; i < tasks.size(); i++) {
            SwarmTask task = tasks.get(i);
            agents.get(i % agents.size()).assign(task);
            LOG.fine("Dispatched " + task.taskId() + " → agent " +
                     agents.get(i % agents.size()).agentId.substring(0,8));
        }

        // Wait
        boolean finished = runLatch.await(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            LOG.warning("SwarmManager run timed out after " + timeoutSeconds + "s");
            for (String tid : List.copyOf(pending)) {
                if (taskIds.contains(tid)) {
                    results.add(TaskResult.cancelled(tid));
                    pending.remove(tid);
                }
            }
        }

        double elapsed = (System.currentTimeMillis() - started) / 1000.0;
        var runResults = results.stream()
            .filter(r -> taskIds.contains(r.taskId()))
            .collect(Collectors.toList());

        return new SwarmResult(
            swarmId,
            tasks.size(),
            (int) runResults.stream().filter(r -> r.status() == TaskStatus.COMPLETED).count(),
            (int) runResults.stream().filter(r -> r.status() == TaskStatus.FAILED).count(),
            (int) runResults.stream().filter(r -> r.status() == TaskStatus.CANCELLED).count(),
            Math.round(elapsed * 100.0) / 100.0,
            runResults
        );
    }

    private SwarmResult emptyResult() {
        return new SwarmResult(swarmId, 0, 0, 0, 0, 0.0, List.of());
    }

    // ── health ────────────────────────────────────────────────────────────────

    public Map<String,Object> health() {
        var agentHealths = pool.values().stream().map(AgentManager::health).collect(Collectors.toList());
        return Map.of(
            "swarmId",      swarmId,
            "poolSize",     pool.size(),
            "idle",         agentHealths.stream().filter(h -> "IDLE".equals(h.get("state"))).count(),
            "running",      agentHealths.stream().filter(h -> "RUNNING".equals(h.get("state"))).count(),
            "pendingTasks", pending.size(),
            "totalDone",    agentHealths.stream().mapToInt(h -> (Integer)h.get("tasksDone")).sum(),
            "totalFailed",  agentHealths.stream().mapToInt(h -> (Integer)h.get("tasksFailed")).sum(),
            "agents",       agentHealths
        );
    }

    public int poolSize() { return pool.size(); }

    // ── shutdown ──────────────────────────────────────────────────────────────

    public void shutdown() {
        shutdown = true;
        pool.values().forEach(AgentManager::shutdown);
        LOG.info("SwarmManager " + swarmId.substring(0,8) + " shut down. " +
                 pool.size() + " agents terminated.");
    }

    @Override public void close() { shutdown(); }

    // ─────────────────────────────────────────────────────────────────────────
    // CLI entry point
    // ─────────────────────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        var handler = new ConsoleHandler();
        handler.setLevel(Level.INFO);
        Logger.getLogger("").addHandler(handler);
        Logger.getLogger("").setLevel(Level.INFO);

        System.out.println("""

            ╔══════════════════════════════════════════════════════════════════╗
            ║     OMNIKON SEC·OPS  —  Swarm Manager  v1.0.2  (Java)          ║
            ║────────────────────────────────────────────────────────────────║
            ║  spawn <n>                   provision n agents                 ║
            ║  run <n> <task1;task2;...>   dispatch tasks to n agents         ║
            ║  react <n> <goal>            ReAct run                         ║
            ║  health                      pool health                        ║
            ║  results                     latest results                     ║
            ║  shutdown                    graceful shutdown                  ║
            ╚══════════════════════════════════════════════════════════════════╝
            """);

        var swarm = new SwarmManager();
        SwarmResult latestResult = null;
        var reader = new BufferedReader(new InputStreamReader(System.in));

        System.out.print("Swarm > ");
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.strip();
            if (line.isEmpty()) { System.out.print("Swarm > "); continue; }

            var parts = line.split("\\s+", 2);
            var cmd   = parts[0].toLowerCase();
            var rest  = parts.length > 1 ? parts[1] : "";

            try {
                switch (cmd) {
                    case "spawn" -> {
                        var sp   = rest.split("\\s+", 2);
                        int n    = Integer.parseInt(sp[0]);
                        var mgrs = swarm.provision(n);
                        System.out.println("✓ Provisioned " + mgrs.size() +
                                           " agents. Pool: " + swarm.poolSize());
                    }
                    case "run" -> {
                        var sp   = rest.split("\\s+", 2);
                        int n    = Integer.parseInt(sp[0]);
                        var objs = sp.length > 1 ? sp[1].split(";") : new String[]{};
                        var tasks = new ArrayList<SwarmTask>();
                        for (int i = 0; i < objs.length; i++) {
                            String obj = objs[i].strip();
                            if (!obj.isEmpty())
                                tasks.add(SwarmTask.of("task_"+(i+1)+"_"+UUID.randomUUID().toString().substring(0,6), obj));
                        }
                        System.out.println("Dispatching " + tasks.size() + " tasks to " + n + " agents…");
                        latestResult = swarm.run(n, tasks, null, 300);
                        System.out.println("\n" + latestResult.summary());
                    }
                    case "react" -> {
                        var sp   = rest.split("\\s+", 2);
                        int n    = Integer.parseInt(sp[0]);
                        String g = sp.length > 1 ? sp[1] : "Investigate";
                        var tasks = List.of(SwarmTask.react("react_"+UUID.randomUUID().toString().substring(0,6), g));
                        System.out.println("ReAct → " + n + " agent(s)…");
                        latestResult = swarm.run(n, tasks, null, 300);
                        System.out.println("\n" + latestResult.summary());
                    }
                    case "health" -> {
                        var h = swarm.health();
                        System.out.printf("Pool: %s | Idle: %s | Running: %s | Pending: %s%n",
                            h.get("poolSize"), h.get("idle"), h.get("running"), h.get("pendingTasks"));
                        @SuppressWarnings("unchecked")
                        var agentHealths = (List<Map<String,Object>>) h.get("agents");
                        for (var a : agentHealths) {
                            System.out.printf("  [%-10s] %s | done=%s failed=%s queue=%s%n",
                                a.get("state"), a.get("agentId").toString().substring(0,8),
                                a.get("tasksDone"), a.get("tasksFailed"), a.get("queueDepth"));
                        }
                    }
                    case "results" -> {
                        if (latestResult == null) { System.out.println("No results yet."); break; }
                        for (var r : latestResult.results()) {
                            System.out.printf("%n  Task %s → %s (%.2fs)%n", r.taskId(), r.status(), r.durationS());
                            System.out.println("  Agent: " + r.agentId().substring(0,8));
                            System.out.println("  Output: " + r.output().substring(0, Math.min(300, r.output().length())));
                            if (!r.error().isEmpty()) System.out.println("  Error: " + r.error());
                        }
                    }
                    case "shutdown", "quit", "exit" -> {
                        swarm.shutdown();
                        System.out.println("✓ Swarm shut down. Goodbye.");
                        return;
                    }
                    default -> System.out.println("Unknown command: " + cmd);
                }
            } catch (Exception e) {
                System.out.println("⚠ " + e.getMessage());
            }
            System.out.print("Swarm > ");
        }
        swarm.shutdown();
    }
}
