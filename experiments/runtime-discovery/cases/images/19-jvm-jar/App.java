/* Loads a class out of a library archive on a signal, and records each
 * load individually.
 *
 * Two logs are written, and they answer different questions.
 *
 *   /var/log/usage.jsonl records, in the shared format, that an archive
 *   was in use.
 *
 *   /var/log/occurrences.jsonl records each individual load with an
 *   identifier of its own: the span it covered, whether it succeeded,
 *   whether it read anything at all, and which file it resolved. A class
 *   already loaded is returned from memory without reading anything, so it
 *   is marked as such: counting it would record a missing observation for
 *   a read that never happened. This program loads the same class twice on
 *   purpose, so both cases appear.
 *
 * The load is deferred to the moment the signal arrives, because a load at
 * startup would happen before the observation is in place, where a
 * collector that works perfectly would still see nothing.
 *
 * In the nested-archive condition the library lives inside this
 * program's own archive. What can be observed there is that the outer file
 * was read; the inner archive is never a file the system opens. The
 * occurrence records the outer file and says so, rather than claiming the
 * inner one was loaded.
 */
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class App {
    private static final String USAGE_LOG = "/var/log/usage.jsonl";
    private static final String OCCURRENCE_LOG = "/var/log/occurrences.jsonl";
    private static final String CASE_ID = env("CASE_ID", "19");
    private static final String FIRE_DIR = env("FIRE_DIR", "/run/fire");
    /* The file the load really reads: the library archive on the class
     * path, or — in the nested condition — this program's own archive,
     * which is the only file that exists to be opened. */
    private static final String TARGET_FILE = env("TARGET_FILE", "/app/log4j-core-2.14.1.jar");
    /* Set in the nested condition, where the evidence covers the outer
     * file and cannot show that the inner archive was loaded on its own. */
    private static final String NESTED_NOTE = env("NESTED_NOTE", "");
    /* How the archive comes to be read: "startup_open" when the runtime
     * opens it before this program runs and holds it open, so a load reads
     * from an existing descriptor and opens nothing; "load_open" when the
     * archive is not on the class path and the load itself opens it. The
     * two produce different observations of the same load, so which one
     * applies is recorded rather than assumed. */
    private static final String OPEN_CONDITION = env("OPEN_CONDITION", "startup_open");
    private static final String TARGET_CLASS = env("TARGET_CLASS", "org.apache.logging.log4j.core.LoggerContext");

    private static String containerID = "";
    private static long occurrenceSeq = 0;
    private static long starttime = 0;

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return (v == null || v.isEmpty()) ? fallback : v;
    }

    /* starttime is field 22 of this process's status line. Field 2 is
     * parenthesized and may itself contain ')', so parsing starts after
     * the last one. */
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
        return String.format("%s.%09dZ",
            now.toString().substring(0, 19), now.getNano());
    }

    private static void append(String file, String line) {
        try (BufferedWriter w = new BufferedWriter(new FileWriter(file, true))) {
            w.write(line);
            w.newLine();
        } catch (IOException e) {
            System.err.println("log write failed: " + e);
        }
    }

    private static void logUsage(String event, String path, boolean ok) {
        append(USAGE_LOG, String.format(
            "{\"ts\":\"%s\",\"pid\":%d,\"starttime\":%d,\"event\":\"%s\",\"path\":\"%s\",\"ok\":%s}",
            stamp(), ProcessHandle.current().pid(), starttime, event, path, ok));
    }

    /* No thread number is recorded here.
     *
     * This runtime's own thread identifier is its own, not the operating
     * system's, and the two are unrelated numbers. Writing it into a field
     * that is compared against an operating-system thread number would
     * make every comparison that used it wrong, in a way that looks like a
     * missed observation. Leaving it out makes the comparison fall back to
     * the process generation, which is correct — and the case definition
     * records that this case cannot be measured at thread granularity. */
    private static void logLoadOccurrence(String start, String end, boolean ok, boolean cacheHit, String file) {
        occurrenceSeq++;
        String note = String.format(",\"open_condition\":\"%s\"", OPEN_CONDITION);
        if (!NESTED_NOTE.isEmpty()) {
            note = note + String.format(",\"note\":\"%s\"", NESTED_NOTE);
        }
        append(OCCURRENCE_LOG, String.format(
            "{\"id\":\"%s-load-%06d\",\"kind\":\"load\",\"pid\":%d,\"starttime\":%d,"
            + "\"start\":\"%s\",\"end\":\"%s\",\"ok\":%s,\"cache_hit\":%s,\"files\":[\"%s\"],"
            + "\"container_id\":\"%s\"%s}",
            CASE_ID, occurrenceSeq, ProcessHandle.current().pid(),
            starttime, start, end, ok, cacheHit, file, containerID, note));
    }

    /* doLoad loads a class and records exactly what that load did.
     *
     * Whether it read anything is decided by whether the class was already
     * loaded, not by whether the call succeeded: a second load succeeds
     * too, from memory. */
    private static void doLoad(String className) {
        ClassLoader loader = loaderForCondition();
        boolean alreadyLoaded = !firstLoads.add(className);
        String start = stamp();
        boolean ok = true;
        try {
            Class.forName(className, true, loader);
        } catch (Throwable t) {
            ok = false;
            System.err.println("load " + className + " failed: " + t);
        }
        String end = stamp();
        logLoadOccurrence(start, end, ok, alreadyLoaded, TARGET_FILE);
        if (ok) {
            logUsage("open", TARGET_FILE, true);
        }
    }

    /* firstLoads is how a read is told from a lookup: the first time this
     * program asks for a class, the archive is read; every later ask for
     * the same class is answered from memory without reading anything.
     *
     * Asking the runtime directly would be better, but the only way to do
     * that reaches into an internal method the runtime refuses to open,
     * and a check that silently fails would report every load as a lookup
     * and empty the denominator. The bookkeeping here is exact for this
     * program because nothing else in it touches the library: the load
     * happens only on the firing signal, and only through this method.
     */
    private static final java.util.Set<String> firstLoads = new java.util.HashSet<>();

    /* lateLoader is the loader used in the condition where the archive is
     * not on the class path. It is built on the firing signal, so the
     * archive is opened by the load rather than by the runtime's own
     * startup — which is the difference the two conditions exist to
     * measure. */
    private static ClassLoader lateLoader;

    private static ClassLoader loaderForCondition() {
        if (!OPEN_CONDITION.equals("load_open")) {
            return App.class.getClassLoader();
        }
        if (lateLoader == null) {
            try {
                /* Every archive the load needs, not only the one being
                 * measured: a library that cannot resolve its own
                 * dependencies fails to load, and a failed load is
                 * recorded as one and leaves the case measuring nothing.
                 * The archive under measurement is still TARGET_FILE, and
                 * that is what the occurrence names. */
                String[] paths = env("LOADER_JARS", TARGET_FILE).split(":");
                java.net.URL[] urls = new java.net.URL[paths.length];
                for (int i = 0; i < paths.length; i++) {
                    urls[i] = new java.io.File(paths[i]).toURI().toURL();
                }
                lateLoader = new java.net.URLClassLoader(urls, App.class.getClassLoader());
            } catch (Exception e) {
                System.err.println("late loader: " + e);
                lateLoader = App.class.getClassLoader();
            }
        }
        return lateLoader;
    }

    /* readNestedEntry reads the inner archive out of the outer one in the
     * nested condition. What this demonstrates is exactly what is
     * observable there: the outer file is read, and the inner archive is
     * never a file the system opens. */
    private static void readNestedEntry(String entry) {
        try (InputStream in = App.class.getClassLoader().getResourceAsStream(entry)) {
            if (in == null) {
                System.err.println("nested entry not found: " + entry);
                return;
            }
            byte[] buf = new byte[8192];
            while (in.read(buf) > 0) {
                // read to the end: the point is that the outer file is read
            }
        } catch (IOException e) {
            System.err.println("nested read failed: " + e);
        }
    }

    private static void waitForSignal() {
        Path fifo = Paths.get(FIRE_DIR, "fire");
        if (!Files.exists(fifo)) {
            return;
        }
        /* A blocking read on a pipe: it runs nothing while it waits, so
         * the wait adds nothing to what is being counted. */
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

    public static void main(String[] args) throws Exception {
        starttime = selfStarttime();
        /* Each container start is its own run; a log left by a previous
         * one would be ground truth for nothing. */
        for (String f : new String[] { USAGE_LOG, OCCURRENCE_LOG }) {
            Files.write(Paths.get(f), new byte[0]);
        }
        logUsage("exec", ProcessHandle.current().info().command().orElse("java"), true);

        waitForSignal();
        containerID = readContainerID();
        logUsage("stage", "fired", true);

        String nested = env("NESTED_ENTRY", "");
        if (!nested.isEmpty()) {
            readNestedEntry(nested);
        }
        /* The first load reads the archive; the second finds the class
         * already in memory and reads nothing. Both are recorded, and only
         * the first belongs in a denominator of expected file reads.
         *
         * What "reads the archive" means depends on how the runtime was
         * started, which is why this case has two conditions. Where the
         * archive is on the class path, the runtime opened it before this
         * program ran and keeps it open; the first load then reads from a
         * descriptor that already exists, and no new opening of the file
         * happens at all. Where the archive is not on the class path, the
         * first load is what opens it. The condition is recorded on the
         * occurrence so a reader is not left to assume the first. */
        doLoad(TARGET_CLASS);
        doLoad(TARGET_CLASS);

        /* Stay alive, and keep the archive open if this runtime keeps it
         * open — whether it does is one of the things being measured. */
        List<Socket> held = new ArrayList<>();
        try (ServerSocket server = new ServerSocket(8080)) {
            while (true) {
                held.add(server.accept());
            }
        }
    }
}
