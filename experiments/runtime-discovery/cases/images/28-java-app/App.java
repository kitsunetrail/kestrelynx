/* Coverage-validation case 28: an HTTP application whose class path and
 * lazily-loaded archives span 12 independent jars across three groups —
 * used_at_startup, used_lazily, and unused (see the case definition's
 * coverage_plan) — run as a workload for measuring how much of a package
 * inventory this harness's sampling, added mapping, and event evidence can
 * independently confirm.
 *
 * Four logs are written, mirroring cases 26 and 27's fixtures.
 *
 *   /var/log/usage.jsonl records, in the shared format, that a jar was in
 *   use.
 *
 *   /var/log/occurrences.jsonl records each individual lazy class load
 *   with an identifier of its own, mirroring case 19's per-load
 *   occurrences.
 *
 *   /var/log/operations.jsonl records each step of the firing procedure
 *   itself, so an independently obtained ground-truth run started from
 *   the same image can be checked against the same operation sequence.
 *
 *   /var/log/runtime-modules.jsonl is written by a helper script
 *   (dump-runtime-modules.sh) invoked at the startup, after-lazy, and
 *   final checkpoints below, from the JVM's own -Xlog:class+load=info
 *   output — this program never inspects its own loaded classes directly,
 *   since the JVM offers no ordinary API for that.
 *
 * The startup-group jars are named directly on this program's launch
 * class path, so the JVM opens each one's central directory before this
 * program runs, whether or not a class inside it is ever loaded; this
 * program also loads one class from each, in startupUse(), so nothing is
 * left on that boundary. The lazy-group jars are never on the launch
 * class path: a class from each is loaded, once fired, through a
 * URLClassLoader this program builds only then — see LazyJacksonUser and
 * LazyCommonsIoUser, compiled against those jars but never linked into
 * this class, so loading them reflectively is what first opens the files.
 * The unused-group jars are copied into the image but named on no class
 * loader's path at all.
 */
import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
    private static final Logger LOG = LoggerFactory.getLogger(App.class);
    private static final Gson GSON = new Gson();

    private static final String USAGE_LOG = "/var/log/usage.jsonl";
    private static final String OCCURRENCE_LOG = "/var/log/occurrences.jsonl";
    private static final String OPERATIONS_LOG = "/var/log/operations.jsonl";
    private static final String CASE_ID = env("CASE_ID", "28");
    private static final String FIRE_DIR = env("FIRE_DIR", "/run/fire");
    private static final int PORT = 8080;
    private static final String LAZY_DIR = "/app/lazy";

    private static String containerID = "";
    private static long occurrenceSeq = 0;
    private static long operationSeq = 0;
    private static long starttime = 0;

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return (v == null || v.isEmpty()) ? fallback : v;
    }

    private static long selfStarttime() {
        try {
            String content = Files.readString(Paths.get("/proc/self/stat"));
            String tail = content.substring(content.lastIndexOf(')') + 1).trim();
            String[] fields = tail.split("\\s+");
            return fields.length > 19 ? Long.parseLong(fields[19]) : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private static String stamp() {
        Instant now = Instant.now();
        return String.format("%s.%09dZ", now.toString().substring(0, 19), now.getNano());
    }

    private static synchronized void appendLine(String file, String line) {
        try {
            Files.writeString(Paths.get(file), line + "\n",
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("log write failed: " + e);
        }
    }

    private static void logUsage(String event, String path, boolean ok) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ts", stamp());
        m.put("pid", ProcessHandle.current().pid());
        m.put("starttime", starttime);
        m.put("event", event);
        m.put("path", path);
        m.put("ok", ok);
        appendLine(USAGE_LOG, GSON.toJson(m));
    }

    private static void logOperation(String op, boolean ok) {
        operationSeq++;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", String.format("%s-op-%06d", CASE_ID, operationSeq));
        m.put("ts", stamp());
        m.put("op", op);
        m.put("ok", ok);
        appendLine(OPERATIONS_LOG, GSON.toJson(m));
    }

    private static void logLoadOccurrence(String start, String end, boolean ok, boolean cacheHit, String jar) {
        occurrenceSeq++;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", String.format("%s-load-%06d", CASE_ID, occurrenceSeq));
        m.put("kind", "load");
        m.put("pid", ProcessHandle.current().pid());
        m.put("starttime", starttime);
        m.put("start", start);
        m.put("end", end);
        m.put("ok", ok);
        m.put("cache_hit", cacheHit);
        m.put("files", new String[] { jar });
        m.put("container_id", containerID);
        appendLine(OCCURRENCE_LOG, GSON.toJson(m));
    }

    /* startupUse exercises the used_at_startup group beyond the bare class
     * load that putting a jar on the launch class path already causes: it
     * calls one real method from each, so nothing in that group stops at
     * "the archive was opened". */
    private static void startupUse() {
        String reversed = StringUtils.reverse("case28");
        String escaped = StringEscapeUtils.escapeHtml4("<case28>");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("reversed", reversed);
        payload.put("escaped", escaped);
        LOG.info("startup use: {}", GSON.toJson(payload));
    }

    /* runLazyLoad loads a helper class through a fresh URLClassLoader
     * spanning exactly the jars named, and records exactly what that did.
     * Whether it read anything is decided by whether the loader had to be
     * built at all for this group; loading the same helper class a second
     * time from an already-built loader is the cache-hit condition,
     * mirroring case 19's doLoad. */
    private static final Map<String, URLClassLoader> lazyLoaders = new LinkedHashMap<>();

    private static void runLazyLoad(String label, String className, String primaryJar, String... jarNames) {
        boolean cacheHit = lazyLoaders.containsKey(label);
        String start = stamp();
        boolean ok = true;
        try {
            URLClassLoader loader = lazyLoaders.computeIfAbsent(label, k -> buildLazyLoader(jarNames));
            Class<?> cls = Class.forName(className, true, loader);
            cls.getMethod("run").invoke(null);
        } catch (Throwable t) {
            ok = false;
            System.err.println("lazy load " + className + " failed: " + t);
        }
        String end = stamp();
        logLoadOccurrence(start, end, ok, cacheHit, primaryJar);
        if (ok && !cacheHit) {
            logUsage("open", primaryJar, true);
        }
        logOperation(label, ok);
    }

    private static URLClassLoader buildLazyLoader(String[] jarNames) {
        try {
            URL lazyClasses = Paths.get(LAZY_DIR, "lazy-classes.jar").toUri().toURL();
            URL[] urls = new URL[jarNames.length + 1];
            urls[0] = lazyClasses;
            for (int i = 0; i < jarNames.length; i++) {
                urls[i + 1] = Paths.get(LAZY_DIR, jarNames[i]).toUri().toURL();
            }
            return new URLClassLoader(urls, App.class.getClassLoader());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void waitForSignal() {
        Path fifo = Paths.get(FIRE_DIR, "fire");
        if (!Files.exists(fifo)) {
            return;
        }
        try (InputStream in = Files.newInputStream(fifo)) {
            in.read();
        } catch (IOException e) {
            System.err.println("signal wait failed: " + e);
        }
    }

    private static String readContainerID() {
        try {
            return Files.readString(Paths.get(FIRE_DIR, "container-id")).trim();
        } catch (IOException e) {
            return "";
        }
    }

    private static void dumpRuntimeModules(String phase) {
        try {
            new ProcessBuilder("/dump-runtime-modules.sh", phase).inheritIO().start().waitFor();
        } catch (Exception e) {
            System.err.println("runtime-modules dump failed: " + e);
        }
    }

    private static HttpServer server;

    private static void handleHealth(HttpExchange ex) throws IOException {
        byte[] body = "ok\n".getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(200, body.length);
        try (var os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    private static void handleLazy(HttpExchange ex, String name) throws IOException {
        switch (name) {
            case "jackson" -> runLazyLoad("request_lazy_jackson", "LazyJacksonUser",
                "jackson-databind-2.17.1.jar", "jackson-databind-2.17.1.jar",
                "jackson-core-2.17.1.jar", "jackson-annotations-2.17.1.jar");
            case "commons-io" -> runLazyLoad("request_lazy_commons-io", "LazyCommonsIoUser",
                "commons-io-2.15.1.jar", "commons-io-2.15.1.jar");
            default -> {
                ex.sendResponseHeaders(404, -1);
                return;
            }
        }
        byte[] body = ("ok " + name + "\n").getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(200, body.length);
        try (var os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    public static void main(String[] args) throws Exception {
        starttime = selfStarttime();
        for (String f : new String[] { USAGE_LOG, OCCURRENCE_LOG, OPERATIONS_LOG }) {
            Files.write(Paths.get(f), new byte[0]);
        }
        logUsage("exec", ProcessHandle.current().info().command().orElse("java"), true);
        dumpRuntimeModules("startup-boot");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> dumpRuntimeModules("final")));

        waitForSignal();
        containerID = readContainerID();
        logUsage("stage", "fired", true);
        logOperation("fired", true);

        startupUse();
        logOperation("startup_use", true);
        dumpRuntimeModules("startup");

        server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
        server.createContext("/health", App::handleHealth);
        server.createContext("/lazy/jackson", ex -> handleLazy(ex, "jackson"));
        server.createContext("/lazy/commons-io", ex -> handleLazy(ex, "commons-io"));
        server.start();

        HttpClient client = HttpClient.newHttpClient();
        for (String name : new String[] { "jackson", "commons-io" }) {
            HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + PORT + "/lazy/" + name)).build();
            client.send(req, HttpResponse.BodyHandlers.discarding());
        }

        dumpRuntimeModules("after_lazy");

        Thread periodic = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(30_000);
                } catch (InterruptedException e) {
                    return;
                }
                dumpRuntimeModules("periodic");
            }
        });
        periodic.setDaemon(true);
        periodic.start();
    }
}
