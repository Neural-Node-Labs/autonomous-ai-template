package memory;

/*
 * =============================================================================
 * MemoryManager.java
 * =============================================================================
 * Project  : OMNIKON SEC·OPS — AI Memory System
 * Version  : v1.0.2
 * Language : Java 17+
 * License  : MIT
 *
 * Production-grade tiered AI Memory Management System — Java port.
 * Zero external runtime dependencies.
 *
 * Layers:
 *   2.1 System Memory    — hard rules / config
 *   2.2 Task Memory      — current task data
 *   2.3 Status Memory    — step / state tracker
 *   2.4 Character Memory — persona / voice / lens
 *   2.5 Reasoning Memory — ReAct loop history (ONLY active when enabled)
 *   Archive              — Append-only JSONL, FileLock, atomic rewrite
 * =============================================================================
 */

import java.io.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import java.util.logging.*;
import java.util.regex.Pattern;
import java.util.stream.*;

// ─────────────────────────────────────────────────────────────────────────────
// Stop-words
// ─────────────────────────────────────────────────────────────────────────────

final class Stopwords {
    static final Set<String> SET = Set.of(
        "a","an","the","and","or","but","in","on","at","to","for","of","with",
        "by","from","is","was","are","were","be","been","has","have","had","do",
        "does","did","not","this","that","it","its","as","so","if","then","than",
        "can","will","would","could","should","may","might","must","shall","about",
        "into","up","out","also","more","no","i","me","my","we","our","you","your"
    );
    private Stopwords() {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector helpers
// ─────────────────────────────────────────────────────────────────────────────

final class VectorUtil {
    private static final Pattern TOKEN = Pattern.compile("[a-z0-9]{2,}");

    static Map<String,Integer> bow(String text) {
        var bow = new HashMap<String,Integer>();
        var m = TOKEN.matcher(text.toLowerCase());
        while (m.find()) {
            var t = m.group();
            if (!Stopwords.SET.contains(t)) bow.merge(t, 1, Integer::sum);
        }
        return bow;
    }

    static double cosine(Map<String,Integer> a, Map<String,Integer> b) {
        if (a.isEmpty() || b.isEmpty()) return 0.0;
        double dot=0, mA=0, mB=0;
        for (var e : a.entrySet()) {
            dot += (double)e.getValue() * b.getOrDefault(e.getKey(),0);
            mA  += (double)e.getValue() * e.getValue();
        }
        for (int v : b.values()) mB += (double)v*v;
        return (mA==0||mB==0) ? 0.0 : dot/(Math.sqrt(mA)*Math.sqrt(mB));
    }

    static String utf8Truncate(String text, int maxBytes) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        return bytes.length <= maxBytes ? text
            : new String(bytes, 0, maxBytes, StandardCharsets.UTF_8);
    }

    static int tokenEstimate(String text) {
        return text.getBytes(StandardCharsets.UTF_8).length / 4;
    }

    private VectorUtil() {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal JSON (flat object / array-of-string; no external deps)
// ─────────────────────────────────────────────────────────────────────────────

final class JsonMini {
    private JsonMini() {}

    @SuppressWarnings("unchecked")
    static Map<String,Object> parse(String json) {
        var result = new LinkedHashMap<String,Object>();
        json = json.trim();
        if (!json.startsWith("{")) return result;
        json = json.substring(1, json.lastIndexOf('}')).trim();
        int i = 0;
        while (i < json.length()) {
            while (i < json.length() && (json.charAt(i)==','||Character.isWhitespace(json.charAt(i)))) i++;
            if (i >= json.length() || json.charAt(i)!='"') break;
            int ks=i+1, ke=json.indexOf('"',ks);
            String key = unescape(json.substring(ks,ke)); i=ke+1;
            while (i < json.length() && json.charAt(i)!=':') i++; i++;
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
            char c = json.charAt(i);
            if (c=='"') {
                int vs=i+1, ve=endQuote(json,vs);
                result.put(key, unescape(json.substring(vs,ve))); i=ve+1;
            } else if (c=='[') {
                int end=json.indexOf(']',i);
                var arr = new ArrayList<Object>();
                if (end > i+1) {
                    for (var part : json.substring(i+1,end).split(",")) {
                        part = part.strip();
                        if (part.startsWith("\"")&&part.endsWith("\""))
                            arr.add(unescape(part.substring(1,part.length()-1)));
                        else arr.add(part);
                    }
                }
                result.put(key, arr); i=end+1;
            } else {
                int vs=i; while (i<json.length()&&json.charAt(i)!=','&&json.charAt(i)!='}') i++;
                String raw=json.substring(vs,i).strip();
                try { result.put(key, Double.parseDouble(raw)); }
                catch (NumberFormatException e) { result.put(key, raw); }
            }
        }
        return result;
    }

    private static int endQuote(String s, int start) {
        for (int i=start;i<s.length();i++) {
            if (s.charAt(i)=='\\'){i++;continue;}
            if (s.charAt(i)=='"') return i;
        }
        return s.length();
    }

    private static String unescape(String s) {
        return s.replace("\\\"","\"").replace("\\n","\n")
                .replace("\\r","\r").replace("\\t","\t").replace("\\\\","\\");
    }

    static String escapeJson(String s) {
        return s.replace("\\","\\\\").replace("\"","\\\"")
                .replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2.5  ReasoningMemory — ReAct trace + loop health monitor
// ─────────────────────────────────────────────────────────────────────────────

enum TraceType { THOUGHT, ACTION, OBSERVATION, FINAL }

record TraceEntry(
    String traceType, int iteration, String content,
    String toolName, boolean isError, int latencyMs, double timestamp
) {
    String shortForm() {
        String prefix  = "["+traceType+" i="+iteration+"]";
        String snippet = content.length()>120 ? content.substring(0,120).replace("\n"," ") : content.replace("\n"," ");
        String tool    = toolName.isEmpty() ? "" : " tool="+toolName;
        String err     = isError ? " ⚠ERROR" : "";
        return prefix+tool+err+" "+snippet;
    }
}

final class ReActLoopMetrics {
    int    totalIterations = 0;
    int    totalToolCalls  = 0;
    int    totalErrors     = 0;
    int    totalLatencyMs  = 0;
    double startedAt       = Instant.now().toEpochMilli()/1000.0;
    double finishedAt      = 0.0;

    double elapsedS() {
        double end = finishedAt > 0 ? finishedAt : Instant.now().toEpochMilli()/1000.0;
        return Math.round((end-startedAt)*100)/100.0;
    }
    double avgIterMs() {
        return totalIterations==0 ? 0.0 : Math.round(totalLatencyMs*10.0/totalIterations)/10.0;
    }
}

public class ReasoningMemory {
    private static final Logger LOG = Logger.getLogger(ReasoningMemory.class.getName());
    static final int PROMPT_BUDGET     = 4_000;
    static final int MAX_ACTIVE_TRACES = 50;

    private final ReentrantLock lock  = new ReentrantLock();
    private final List<TraceEntry>  traces  = new ArrayList<>();
    private ReActLoopMetrics        metrics = new ReActLoopMetrics();
    private String                  goal_   = "";
    private boolean                 enabled_= false;

    public void enable(String goal) {
        lock.lock();
        try {
            enabled_ = true;
            traces.clear();
            metrics  = new ReActLoopMetrics();
            goal_    = goal==null?"":goal.strip();
        } finally { lock.unlock(); }
        LOG.info("ReasoningMemory: enabled — goal="+goal_);
    }

    public void disable() {
        lock.lock(); try { enabled_=false; } finally { lock.unlock(); }
        LOG.info("ReasoningMemory: disabled.");
    }

    public boolean isEnabled() { lock.lock(); try { return enabled_; } finally { lock.unlock(); } }
    public String  getGoal()   { lock.lock(); try { return goal_;    } finally { lock.unlock(); } }

    public TraceEntry record(TraceType type, String content,
                             String toolName, boolean isError, int latencyMs) {
        if (!enabled_) throw new IllegalStateException("ReasoningMemory.record called while disabled.");
        lock.lock();
        try {
            metrics.totalIterations++;
            if (type==TraceType.ACTION)  metrics.totalToolCalls++;
            if (isError)                 metrics.totalErrors++;
            metrics.totalLatencyMs += latencyMs;
            var entry = new TraceEntry(
                type.name(), metrics.totalIterations,
                content==null?"":content.strip(),
                toolName==null?"":toolName, isError, latencyMs,
                Instant.now().toEpochMilli()/1000.0
            );
            traces.add(entry);
            if (traces.size() > MAX_ACTIVE_TRACES) traces.subList(0, traces.size()-MAX_ACTIVE_TRACES).clear();
            LOG.fine("ReAct: "+entry.shortForm());
            return entry;
        } finally { lock.unlock(); }
    }

    public TraceEntry record(TraceType type, String content) {
        return record(type, content, "", false, 0);
    }

    public void finish(String finalAnswer) {
        lock.lock(); try { metrics.finishedAt = Instant.now().toEpochMilli()/1000.0; } finally { lock.unlock(); }
        if (finalAnswer!=null && !finalAnswer.isBlank()) record(TraceType.FINAL, finalAnswer);
        var m = metrics;
        LOG.info(String.format("ReAct done: iters=%d tools=%d errors=%d elapsed=%.2fs",
            m.totalIterations, m.totalToolCalls, m.totalErrors, m.elapsedS()));
    }

    public String promptBlock() {
        lock.lock();
        try {
            if (!enabled_ || traces.isEmpty()) return "";
            var m = metrics;
            var sb = new StringBuilder();
            sb.append("## ReAct Reasoning Trace (layer 2.5)\n");
            sb.append("Goal      : ").append(goal_.isEmpty()?"(not set)":goal_).append("\n");
            sb.append(String.format("Iterations: %d | Tool calls: %d | Errors: %d | Elapsed: %.2fs | Avg/iter: %.1fms%n",
                m.totalIterations, m.totalToolCalls, m.totalErrors, m.elapsedS(), m.avgIterMs()));
            sb.append("\nRecent steps (last 10):\n");
            int start = Math.max(0, traces.size()-10);
            for (int i=start;i<traces.size();i++) sb.append("  ").append(traces.get(i).shortForm()).append("\n");
            return VectorUtil.utf8Truncate(sb.toString(), PROMPT_BUDGET);
        } finally { lock.unlock(); }
    }

    public String toArchiveContent() {
        lock.lock();
        try {
            var m = metrics;
            var sb = new StringBuilder();
            sb.append("[ReAct Trace] goal=\"").append(JsonMini.escapeJson(goal_)).append("\"\n");
            sb.append(String.format("iterations=%d tool_calls=%d errors=%d elapsed=%.2fs%n",
                m.totalIterations, m.totalToolCalls, m.totalErrors, m.elapsedS()));
            sb.append("---\n");
            for (var t : traces) sb.append(t.shortForm()).append("\n");
            return sb.toString();
        } finally { lock.unlock(); }
    }

    public List<TraceEntry> getTraces()   { lock.lock(); try { return new ArrayList<>(traces); } finally { lock.unlock(); } }
    public ReActLoopMetrics getMetrics()  { lock.lock(); try { return metrics; } finally { lock.unlock(); } }
    public String lastObservation() {
        lock.lock();
        try {
            for (int i=traces.size()-1;i>=0;i--)
                if (traces.get(i).traceType().equals("OBSERVATION")) return traces.get(i).content();
            return "";
        } finally { lock.unlock(); }
    }

    public Map<String,Object> snapshotMap() {
        var m = getMetrics();
        return Map.of(
            "enabled",          isEnabled(),  "goal",             getGoal(),
            "totalIterations",  m.totalIterations, "totalToolCalls", m.totalToolCalls,
            "totalErrors",      m.totalErrors, "elapsedS",        m.elapsedS(),
            "avgIterMs",        m.avgIterMs(), "traceCount",      getTraces().size()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchiveEntry
// ─────────────────────────────────────────────────────────────────────────────

record ArchiveEntry(String id, double timestamp, String source, String content, List<String> tags) {
    ArchiveEntry {
        if (id==null||id.isBlank()) throw new IllegalArgumentException("id blank");
        if (content==null||content.isBlank()) throw new IllegalArgumentException("content blank");
        tags = List.copyOf(tags!=null?tags:List.of());
    }

    String toJsonLine() {
        var tagJson = tags.stream()
            .map(t->"\""+JsonMini.escapeJson(t)+"\"")
            .collect(Collectors.joining(",","[","]"));
        return String.format("{\"id\":\"%s\",\"timestamp\":%.6f,\"source\":\"%s\",\"content\":\"%s\",\"tags\":%s}",
            JsonMini.escapeJson(id), timestamp, JsonMini.escapeJson(source),
            JsonMini.escapeJson(content), tagJson);
    }

    @SuppressWarnings("unchecked")
    static ArchiveEntry fromLine(String line) {
        var m   = JsonMini.parse(line);
        var id  = (String) m.getOrDefault("id","");
        var ts  = ((Number) m.getOrDefault("timestamp",0.0)).doubleValue();
        var src = (String) m.getOrDefault("source","manual");
        var con = (String) m.getOrDefault("content","");
        var raw = (List<Object>) m.getOrDefault("tags", List.of());
        var tgs = raw.stream().map(Object::toString).collect(Collectors.toList());
        return new ArchiveEntry(id, ts, src, con, tgs);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaskStatus
// ─────────────────────────────────────────────────────────────────────────────

final class TaskStatus {
    String       objective   = "";
    int          totalSteps  = 0;
    int          currentStep = 0;
    List<String> completed   = new ArrayList<>();
    List<String> pending     = new ArrayList<>();
    String       notes       = "";

    boolean isActive() { return !objective.isBlank(); }
    double  progressPct() { return totalSteps==0?0.0:Math.round(currentStep*1000.0/totalSteps)/10.0; }

    String summary() {
        if (!isActive()) return "[STATUS] No active task.";
        String prog = totalSteps>0
            ? "Step "+currentStep+"/"+totalSteps+" ("+progressPct()+"%)" : "—";
        var sb = new StringBuilder();
        sb.append("[STATUS] ").append(prog).append(" | Objective: ").append(objective).append('\n');
        sb.append("  Done   : ").append(completed.isEmpty()?"none":String.join(", ",completed)).append('\n');
        sb.append("  Pending: ").append(pending.isEmpty()?"none":String.join(", ",pending));
        if (!notes.isBlank()) sb.append('\n').append("  Notes  : ").append(notes);
        return sb.toString();
    }

    void reset() { objective=""; totalSteps=0; currentStep=0; completed.clear(); pending.clear(); notes=""; }
}

// ─────────────────────────────────────────────────────────────────────────────
// CharacterMemory
// ─────────────────────────────────────────────────────────────────────────────

final class CharacterMemory {
    String       name           = "Assistant";
    String       tone           = "professional";
    List<String> expertise      = new ArrayList<>();
    String       personality    = "";
    String       responseFormat = "Markdown";
    List<String> constraints    = new ArrayList<>();

    String personaBlock() {
        var sb = new StringBuilder();
        sb.append("You are ").append(name).append(".\n");
        sb.append("Tone: ").append(tone).append(".\n");
        sb.append("Expertise: ").append(expertise.isEmpty()?"general":String.join(", ",expertise)).append(".\n");
        sb.append("Always respond in: ").append(responseFormat).append(".");
        if (!personality.isBlank()) sb.append("\nPersonality: ").append(personality);
        for (var c : constraints) sb.append("\nCONSTRAINT: ").append(c);
        return sb.toString();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Archive
// ─────────────────────────────────────────────────────────────────────────────

class Archive {
    private static final Logger LOG = Logger.getLogger(Archive.class.getName());
    private final Path path;
    private final List<ArchiveEntry>      entries = new CopyOnWriteArrayList<>();
    private final ReentrantReadWriteLock  rwLock  = new ReentrantReadWriteLock();

    Archive(Path path) { this.path=path; load(); }

    private void load() {
        if (!Files.exists(path)) return;
        int ok=0, bad=0;
        try (var br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line; int n=0;
            while ((line=br.readLine())!=null) {
                n++; line=line.strip();
                if (line.isEmpty()) continue;
                try { entries.add(ArchiveEntry.fromLine(line)); ok++; }
                catch (Exception e) { LOG.warning("Archive: corrupt line "+n+": "+e.getMessage()); bad++; }
            }
        } catch (IOException e) { LOG.severe("Archive load failed: "+e.getMessage()); }
        LOG.info(String.format("Archive: loaded %d (%d skipped) from %s",ok,bad,path));
    }

    private void appendDisk(ArchiveEntry e) throws IOException {
        try (var fc = FileChannel.open(path,
                StandardOpenOption.CREATE,StandardOpenOption.APPEND,StandardOpenOption.WRITE);
             FileLock lk = fc.lock()) {
            byte[] data = (e.toJsonLine()+"\n").getBytes(StandardCharsets.UTF_8);
            fc.write(java.nio.ByteBuffer.wrap(data)); fc.force(true);
        }
    }

    private void rewriteDisk() throws IOException {
        Path dir = path.getParent()!=null?path.getParent():Path.of(".");
        Path tmp = Files.createTempFile(dir,".arc_",".tmp");
        try {
            try (var fc = FileChannel.open(tmp,StandardOpenOption.WRITE,
                    StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING);
                 FileLock lk = fc.lock();
                 var bw = new BufferedWriter(new OutputStreamWriter(
                     java.nio.channels.Channels.newOutputStream(fc), StandardCharsets.UTF_8))) {
                for (var entry : entries) { bw.write(entry.toJsonLine()); bw.newLine(); }
                bw.flush(); fc.force(true);
            }
            Files.move(tmp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException ex) { try{Files.deleteIfExists(tmp);}catch(IOException ignore){} throw ex; }
    }

    ArchiveEntry store(String content, String source, List<String> tags) {
        if (content==null||content.isBlank()) throw new IllegalArgumentException("content blank");
        var e = new ArchiveEntry(java.util.UUID.randomUUID().toString(),
            Instant.now().toEpochMilli()/1000.0,
            source!=null?source:"manual", content.strip(), tags!=null?tags:List.of());
        rwLock.writeLock().lock();
        try { entries.add(e); appendDisk(e); }
        catch (IOException ex) { LOG.severe("Archive.store disk error: "+ex.getMessage()); }
        finally { rwLock.writeLock().unlock(); }
        return e;
    }

    List<ArchiveEntry> retrieve(String query, int topK, double minScore) {
        if (query==null||query.isBlank()) return List.of();
        var qv = VectorUtil.bow(query);
        List<ArchiveEntry> snap;
        rwLock.readLock().lock(); try { snap=new ArrayList<>(entries); } finally { rwLock.readLock().unlock(); }
        record Scored(ArchiveEntry e, double s){}
        return snap.stream()
            .map(e->new Scored(e, VectorUtil.cosine(qv, VectorUtil.bow(e.content()))))
            .filter(s->s.s()>=minScore)
            .sorted(Comparator.comparingDouble(Scored::s).reversed())
            .limit(topK).map(Scored::e).collect(Collectors.toList());
    }

    boolean delete(String id) {
        rwLock.writeLock().lock();
        try {
            boolean removed = entries.removeIf(e->e.id().equals(id));
            if (removed) rewriteDisk();
            return removed;
        } catch (IOException e) { LOG.severe("Archive.delete rewrite failed: "+e.getMessage()); return false; }
        finally { rwLock.writeLock().unlock(); }
    }

    Optional<ArchiveEntry> get(String id) {
        rwLock.readLock().lock();
        try { return entries.stream().filter(e->e.id().equals(id)).findFirst(); }
        finally { rwLock.readLock().unlock(); }
    }

    List<ArchiveEntry> allEntries() { rwLock.readLock().lock(); try{return new ArrayList<>(entries);}finally{rwLock.readLock().unlock();} }
    int size() { return entries.size(); }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkingMemory  (layers 2.1 – 2.5)
// ─────────────────────────────────────────────────────────────────────────────

final class WorkingMemory {
    private static final Logger LOG = Logger.getLogger(WorkingMemory.class.getName());
    private static final Map<String,Integer> BUDGET = Map.of(
        "character",1_500,"system",3_000,"status",1_200,
        "reasoning",4_000,"retrieved",6_000,"task",12_000);
    static final int SUMMARIZE_THRESHOLD = 6_000;
    int keepTurns = 4;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final List<String> systemRules = new ArrayList<>();
    private final List<String> taskContent = new ArrayList<>();
    private final List<Map<String,String>> history = new ArrayList<>();
    private final TaskStatus       status    = new TaskStatus();
    private final CharacterMemory  character = new CharacterMemory();
    private final ReasoningMemory  reasoning = new ReasoningMemory();
    private List<ArchiveEntry>     retrieved = new ArrayList<>();

    CharacterMemory character() { return character; }
    TaskStatus      status()    { return status; }
    ReasoningMemory reasoning() { return reasoning; }

    List<String> getSystemRules() { lock.readLock().lock(); try{return new ArrayList<>(systemRules);}finally{lock.readLock().unlock();} }
    List<String> getTaskContent() { lock.readLock().lock(); try{return new ArrayList<>(taskContent);}finally{lock.readLock().unlock();} }
    List<Map<String,String>> getHistory() { lock.readLock().lock(); try{return new ArrayList<>(history);}finally{lock.readLock().unlock();} }
    int retrievedCount() { lock.readLock().lock(); try{return retrieved.size();}finally{lock.readLock().unlock();} }

    void addSystemRule(String rule) {
        if (rule==null||rule.isBlank()) return;
        rule = rule.strip();
        lock.writeLock().lock(); try { if(!systemRules.contains(rule))systemRules.add(rule); } finally{lock.writeLock().unlock();}
    }
    void addTaskContent(String c) {
        if (c!=null&&!c.isBlank()) { lock.writeLock().lock(); try{taskContent.add(c.strip());}finally{lock.writeLock().unlock();} }
    }
    void addMessage(String role, String content) {
        if (!Set.of("user","assistant","system").contains(role)) throw new IllegalArgumentException("Invalid role: "+role);
        lock.writeLock().lock(); try{history.add(Map.of("role",role,"content",content));}finally{lock.writeLock().unlock();}
    }
    void injectRetrieved(List<ArchiveEntry> entries) {
        lock.writeLock().lock(); try{retrieved=new ArrayList<>(entries);}finally{lock.writeLock().unlock();}
    }
    void clearTask() {
        lock.writeLock().lock();
        try{ taskContent.clear(); history.clear(); retrieved.clear(); status.reset(); }
        finally{lock.writeLock().unlock();}
        LOG.fine("WorkingMemory: task cleared.");
    }

    List<Map<String,String>> popOldTurns() {
        lock.writeLock().lock();
        try {
            var h = new ArrayList<>(history);
            if (h.size()<=keepTurns) return List.of();
            var old = new ArrayList<>(h.subList(0, h.size()-keepTurns));
            history.clear(); history.addAll(h.subList(h.size()-keepTurns, h.size()));
            return old;
        } finally{lock.writeLock().unlock();}
    }

    private String truncate(String text, int maxChars, String label) {
        if (text.length()<=maxChars) return text;
        int half=maxChars/2;
        LOG.warning(String.format("WorkingMemory: '%s' truncated %d→%d", label, text.length(), maxChars));
        return VectorUtil.utf8Truncate(text, half) + "\n…[truncated]…\n" + text.substring(text.length()-half);
    }

    String buildSystemPrompt() {
        lock.readLock().lock();
        try {
            var parts = new ArrayList<String>();
            parts.add(truncate(character.personaBlock(), BUDGET.get("character"), "character"));
            if (!systemRules.isEmpty()) {
                var block = systemRules.stream().map(r->"• "+r).collect(Collectors.joining("\n"));
                parts.add("## System Rules\n" + truncate(block, BUDGET.get("system"), "system"));
            }
            if (status.isActive()) parts.add(truncate(status.summary(), BUDGET.get("status"), "status"));

            // 2.5 Reasoning — only when ReAct active
            var rb = reasoning.promptBlock();
            if (!rb.isEmpty()) parts.add(truncate(rb, BUDGET.get("reasoning"), "reasoning"));

            if (!retrieved.isEmpty()) {
                var sb = new StringBuilder();
                for (int i=0;i<retrieved.size();i++) {
                    if (sb.length()>0) sb.append("\n\n");
                    sb.append("[Memory ").append(i+1).append("] (source: ").append(retrieved.get(i).source()).append(")\n")
                      .append(retrieved.get(i).content());
                }
                parts.add("## Relevant Memory\n" + truncate(sb.toString(), BUDGET.get("retrieved"), "retrieved"));
            }
            if (!taskContent.isEmpty()) {
                var raw = String.join("\n\n", taskContent);
                parts.add("## Task Context\n" + truncate(raw, BUDGET.get("task"), "task"));
            }
            return String.join("\n\n---\n\n", parts);
        } finally{lock.readLock().unlock();}
    }

    List<Map<String,String>> buildMessages() {
        lock.readLock().lock(); try{return new ArrayList<>(history);}finally{lock.readLock().unlock();}
    }

    int tokenEstimate() {
        lock.readLock().lock();
        try {
            String prompt = buildSystemPrompt();
            String hist   = history.stream().map(m->m.get("content")).collect(Collectors.joining(" "));
            return VectorUtil.tokenEstimate(prompt+" "+hist);
        } finally{lock.readLock().unlock();}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryManager — unified orchestrator
// ─────────────────────────────────────────────────────────────────────────────

class MemoryManager {
    private static final Logger LOG = Logger.getLogger(MemoryManager.class.getName());

    final Archive       archive;
    final WorkingMemory working;

    MemoryManager(Path archivePath) {
        this.archive = new Archive(archivePath);
        this.working = new WorkingMemory();
        LOG.info("MemoryManager v3 ready. Archive: "+archivePath);
    }

    // proxies
    CharacterMemory character() { return working.character(); }
    TaskStatus      status()    { return working.status(); }
    ReasoningMemory react()     { return working.reasoning(); }

    void addSystemRule(String r)      { working.addSystemRule(r); }
    void addTaskContent(String c)     { working.addTaskContent(c); }
    void addUserMessage(String c)     { working.addMessage("user",c); }
    void addAssistantMessage(String c){ working.addMessage("assistant",c); }

    // task lifecycle
    void startTask(String objective, List<String> steps) {
        if (objective==null||objective.isBlank()) throw new IllegalArgumentException("objective blank");
        working.clearTask();
        working.status().objective = objective.strip();
        if (steps!=null&&!steps.isEmpty()) {
            var clean = steps.stream().filter(s->!s.isBlank()).map(String::strip).collect(Collectors.toList());
            working.status().totalSteps = clean.size();
            working.status().pending.addAll(clean);
        }
        LOG.info("Task started: "+objective);
    }

    void completeStep(String label) {
        var s = working.status();
        if (!s.isActive()) throw new IllegalStateException("No active task.");
        String lbl = (label!=null&&!label.isBlank()) ? label.strip()
                   : (!s.pending.isEmpty() ? s.pending.get(0) : "Step "+(s.currentStep+1));
        if (!s.pending.isEmpty()) s.pending.remove(0);
        s.completed.add(lbl); s.currentStep++;
    }

    ArchiveEntry finishTask(String summary) {
        var s = working.status();
        if (!s.isActive()) throw new IllegalStateException("No active task.");
        var parts = new ArrayList<String>();
        parts.add("Task: "+s.objective);
        if (summary!=null&&!summary.isBlank()) parts.add("Summary: "+summary.strip());
        if (!s.completed.isEmpty()) parts.add("Completed: "+String.join("; ",s.completed));
        var tc = working.getTaskContent();
        if (!tc.isEmpty()) parts.add("Snapshot:\n"+String.join("\n",tc.subList(0,Math.min(3,tc.size()))));
        var entry = archive.store(String.join("\n",parts), "task_summary",
            List.of("task", s.objective.substring(0,Math.min(40,s.objective.length()))));
        LOG.info("Task archived: id="+entry.id());
        working.clearTask();
        return entry;
    }

    // ReAct lifecycle
    void enableReact(String goal) { working.reasoning().enable(goal); }

    Optional<ArchiveEntry> finishReact(String finalAnswer) {
        var rm = working.reasoning();
        if (!rm.isEnabled()) return Optional.empty();
        rm.finish(finalAnswer);
        var content = rm.toArchiveContent();
        Optional<ArchiveEntry> entry = Optional.empty();
        if (!content.isBlank()) {
            var e = archive.store(content, "react_trace",
                List.of("react","reasoning", rm.getGoal().substring(0,Math.min(40,rm.getGoal().length()))));
            LOG.info("ReAct trace archived: id="+e.id());
            entry = Optional.of(e);
        }
        rm.disable();
        return entry;
    }

    // context
    String contextForQuery(String query, int topK, double minScore) {
        if (working.tokenEstimate() > WorkingMemory.SUMMARIZE_THRESHOLD) summarize();
        var hits = archive.retrieve(query, topK, minScore);
        working.injectRetrieved(hits);
        return working.buildSystemPrompt();
    }

    private void summarize() {
        var old = working.popOldTurns();
        if (old.isEmpty()) return;
        var lines = old.stream()
            .map(m -> m.get("role").toUpperCase()+": "+m.get("content").substring(0,Math.min(300,m.get("content").length())))
            .collect(Collectors.joining("\n"));
        archive.store("[Conversation summary]\n"+lines, "conversation", List.of("summary","auto"));
        LOG.info("Summarised "+old.size()+" turns.");
    }

    Map<String,Object> snapshot() {
        var s = working.status();
        var base = new LinkedHashMap<String,Object>();
        base.put("characterName",    working.character().name);
        base.put("systemRuleCount",  working.getSystemRules().size());
        base.put("taskObjective",    s.objective);
        base.put("taskProgressPct",  s.progressPct());
        base.put("taskCurrentStep",  s.currentStep);
        base.put("taskTotalSteps",   s.totalSteps);
        base.put("conversationTurns",working.getHistory().size());
        base.put("retrievedCount",   working.retrievedCount());
        base.put("archiveTotal",     archive.size());
        base.put("estimatedTokens",  working.tokenEstimate());
        base.put("reactEnabled",     working.reasoning().isEnabled());
        if (working.reasoning().isEnabled()) base.put("reasoning", working.reasoning().snapshotMap());
        return base;
    }

    @Override
    public String toString() {
        var s = snapshot();
        return "<MemoryManager | archive="+s.get("archiveTotal")
            +" | tokens≈"+s.get("estimatedTokens")
            +" | task='"+s.get("taskObjective")+"'"
            +" | react="+(Boolean.TRUE.equals(s.get("reactEnabled"))?"ON":"OFF")+">";
    }
}
