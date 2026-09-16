/* Loads a shared library, holds it for seven seconds, unloads it, stays
 * unloaded for seven seconds, and repeats — after being told to start.
 *
 * Unlike a language runtime's own module bookkeeping, which typically
 * never unloads anything, this unloads explicitly and then checks that the
 * mapping is really gone. That check is what defines a non-loaded period
 * here: the unload call returning is not the same as the file no longer
 * being mapped.
 *
 * Two logs are written, and they answer different questions.
 *
 *   /var/log/usage.jsonl records, in the shared format, that the library
 *   was in use over a span of time.
 *
 *   /var/log/occurrences.jsonl records each individual load with an
 *   identifier of its own, the span it covered, whether it succeeded, and
 *   whether it had to read the file at all. That last field matters: a
 *   load satisfied from what the runtime already holds reads nothing, so
 *   counting it would record a missing observation for a file read that
 *   never happened. Here every load does read the file, and the check
 *   after each unload is what establishes that.
 *
 * Nothing starts until the signal arrives, because a load that happens
 * while the observation is still starting up would be missed by a
 * collector that works perfectly.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *kLibraryPath = "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0";
static const char *kUsageLog = "/var/log/usage.jsonl";
static const char *kOccurrenceLog = "/var/log/occurrences.jsonl";

static char gContainerID[128];
static char gCaseID[64] = "14";

static long selfStarttime(void) {
    FILE *f = fopen("/proc/self/stat", "r");
    if (!f) {
        return 0;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) {
        return 0;
    }
    buf[n] = '\0';
    /* Field 2 is parenthesized and may itself contain ')'; start parsing
     * after the last one. */
    char *closeParen = strrchr(buf, ')');
    if (!closeParen) {
        return 0;
    }
    long starttime = 0;
    int field = 0; /* fields after the parenthesized one: state is 0 here */
    char *tok = strtok(closeParen + 1, " ");
    while (tok) {
        if (field == 19) { /* overall field 22 */
            starttime = atol(tok);
            break;
        }
        tok = strtok(NULL, " ");
        field++;
    }
    return starttime;
}

static void nowStamp(char *out, size_t len) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out, len, "%s.%09ldZ", base, ts.tv_nsec);
}

/* mappingPresent reports whether the library still appears in this
 * process's own list of mapped files. It is the evidence behind both the
 * "the file was really read" and the "the file is really gone" claims,
 * neither of which the load and unload calls establish by themselves. */
static int mappingPresent(const char *needle) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        return -1;
    }
    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static void appendLine(const char *path, const char *line) {
    FILE *f = fopen(path, "a");
    if (!f) {
        return;
    }
    fputs(line, f);
    fclose(f);
}

static void logUsage(long pid, long starttime, const char *event, const char *path, const char *ok, const char *extra) {
    char ts[64];
    nowStamp(ts, sizeof(ts));
    char line[8192];
    snprintf(line, sizeof(line),
             "{\"ts\":\"%s\",\"pid\":%ld,\"starttime\":%ld,\"event\":\"%s\",\"path\":\"%s\",\"ok\":%s%s}\n",
             ts, pid, starttime, event, path, ok, extra ? extra : "");
    appendLine(kUsageLog, line);
}

static void logLoadOccurrence(long seq, long pid, long starttime,
                              const char *start, const char *end, const char *ok,
                              const char *cacheHit, const char *file) {
    char line[8192];
    snprintf(line, sizeof(line),
             "{\"id\":\"%s-load-%06ld\",\"kind\":\"load\",\"pid\":%ld,\"tid\":%ld,\"starttime\":%ld,"
             "\"start\":\"%s\",\"end\":\"%s\",\"ok\":%s,\"cache_hit\":%s,\"files\":[\"%s\"],"
             "\"container_id\":\"%s\"}\n",
             gCaseID, seq, pid, pid, starttime, start, end, ok, cacheHit, file, gContainerID);
    appendLine(kOccurrenceLog, line);
}

/* waitForSignal blocks on a pipe until something is written to it. A
 * blocking read runs nothing while it waits, so the wait itself does not
 * add to what this case is counting. */
static void waitForSignal(const char *dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/fire", dir);
    FILE *f = fopen(path, "r");
    if (!f) {
        return; /* no signalling directory: start immediately */
    }
    char buf[256];
    if (fgets(buf, sizeof(buf), f) == NULL) {
        /* the writer closed without sending anything; start anyway */
    }
    fclose(f);
}

static void readContainerID(const char *dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/container-id", dir);
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }
    if (fgets(gContainerID, sizeof(gContainerID), f)) {
        gContainerID[strcspn(gContainerID, "\r\n")] = '\0';
    }
    fclose(f);
}

/* gUnloadVerified records whether the previous cycle's unload was
 * confirmed to have removed the mapping. It decides what the next load can
 * honestly claim: only after a verified unload is the library certainly
 * read from the file again. Where the unload was not confirmed, the next
 * load may have been satisfied from what was already mapped, and saying
 * otherwise would put a file read that never happened into the
 * denominator. */
static int gUnloadVerified = 1;

int main(void) {
    const char *fireDir = getenv("FIRE_DIR");
    if (!fireDir) {
        fireDir = "/run/fire";
    }
    const char *envCaseID = getenv("CASE_ID");
    if (envCaseID && *envCaseID) {
        snprintf(gCaseID, sizeof(gCaseID), "%s", envCaseID);
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    long pid = (long)getpid();
    long starttime = selfStarttime();

    /* Each container start is its own run; a log left by a previous one
     * would be ground truth for nothing. */
    fclose(fopen(kUsageLog, "w"));
    fclose(fopen(kOccurrenceLog, "w"));

    waitForSignal(fireDir);
    readContainerID(fireDir);
    logUsage(pid, starttime, "stage", "fired", "true", NULL);
    logUsage(pid, starttime, "exec", "/dlopen_loop", "true", NULL);

    for (long seq = 1;; seq++) {
        char startStamp[64], endStamp[64];
        nowStamp(startStamp, sizeof(startStamp));
        void *handle = dlopen(kLibraryPath, RTLD_NOW);
        nowStamp(endStamp, sizeof(endStamp));
        int present = handle ? mappingPresent("libsqlite3") : 0;
        const char *ok = handle ? "true" : "false";
        /* Whether this load read the file depends on whether the previous
         * cycle's unload was confirmed to have removed the mapping. After
         * a confirmed unload nothing was held over and the file is read
         * again; without that confirmation the load may have been
         * satisfied from what was still mapped, and it is recorded as
         * such so it stays out of the denominator of expected reads. */
        const char *cacheHit = gUnloadVerified ? "false" : "true";
        logLoadOccurrence(seq, pid, starttime, startStamp, endStamp, ok, cacheHit, kLibraryPath);
        logUsage(pid, starttime, "dlopen", kLibraryPath, ok, NULL);
        if (handle && present == 1) {
            logUsage(pid, starttime, "open", kLibraryPath, "true", NULL);
        }
        if (!handle) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            gUnloadVerified = 0;
            sleep(7);
            continue;
        }

        sleep(7);
        dlclose(handle);
        int stillThere = mappingPresent("libsqlite3");
        /* A read that failed leaves the question open, and an open
         * question is not a confirmed unload. */
        gUnloadVerified = (stillThere == 0);
        logUsage(pid, starttime, "dlclose", kLibraryPath, "true",
                 stillThere == 0 ? ",\"maps_unloaded\":true" : ",\"maps_unloaded\":false");
        sleep(7);
    }
    return 0;
}
