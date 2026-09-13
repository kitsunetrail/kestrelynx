/* Explicit dlopen/dlclose loop for the R10 test case: loads libsqlite3,
 * holds it for 7 seconds, dlcloses it, then stays unloaded for 7 seconds,
 * repeating. Unlike a language runtime's own module-cache reference
 * counting (e.g. Python's ctypes.CDLL, which never calls dlclose), this
 * explicitly and verifiably unmaps the library every other cycle.
 *
 * Every event is logged to /var/log/usage.jsonl in the common format this
 * harness's other self-built test images also use:
 *   {"ts":"<RFC3339Nano>","pid":<int>,"starttime":<int>,"event":"exec|dlopen|dlclose|open","path":"<path>","ok":true|false}
 * "open" additionally records that a /proc/self/maps snapshot taken right
 * after dlopen actually shows the mapping, since that snapshot — not the
 * dlopen return value alone — is the ground truth this case's usage log is
 * meant to provide.
 *
 * The dlclose event carries one extra field beyond the common six,
 * "maps_unloaded": whether a /proc/self/maps snapshot taken right after
 * dlclose could be read and no longer shows the mapping. That is the
 * case's own definition of a non-loaded period, so a reader waiting for
 * this case to be ready waits for that field to be true rather than for a
 * dlclose line to merely exist. A consumer of the common format ignores
 * the extra field. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char *kLibraryPath = "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0";

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
    /* Field 2 (comm) is parenthesized and may itself contain ')'; start
     * parsing after the *last* ')'. */
    char *close = strrchr(buf, ')');
    if (!close) {
        return 0;
    }
    long starttime = 0;
    int field = 0; /* fields after comm: state is field 0 here */
    char *tok = strtok(close + 1, " ");
    while (tok) {
        if (field == 19) { /* starttime is overall field 22 = post-comm field 19 */
            starttime = atol(tok);
            break;
        }
        tok = strtok(NULL, " ");
        field++;
    }
    return starttime;
}

/* logEventExtra writes one common-format line, optionally followed by one
 * extra field (extraName/extraValue, already JSON-encoded). Timestamps
 * carry nanoseconds: a 7s/7s cycle is coarse, but the harness correlates
 * these events with samples whose own timestamps are nanosecond-precise,
 * and a whole-second stamp would make "which side of the sample did this
 * happen on" unanswerable. */
static void logEventExtra(long starttime, const char *event, const char *path, int ok,
                          const char *extraName, const char *extraValue) {
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return;
    }
    struct tm tmv;
    gmtime_r(&now.tv_sec, &tmv);
    char stamp[40];
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tmv);

    FILE *f = fopen("/var/log/usage.jsonl", "a");
    if (!f) {
        return;
    }
    fprintf(f, "{\"ts\":\"%s.%09ldZ\",\"pid\":%d,\"starttime\":%ld,\"event\":\"%s\",\"path\":\"%s\",\"ok\":%s",
            stamp, (long)now.tv_nsec, (int)getpid(), starttime, event, path, ok ? "true" : "false");
    if (extraName != NULL) {
        fprintf(f, ",\"%s\":%s", extraName, extraValue);
    }
    fprintf(f, "}\n");
    fclose(f);
}

static void logEvent(long starttime, const char *event, const char *path, int ok) {
    logEventExtra(starttime, event, path, ok, NULL, NULL);
}

/* mapsShowsLibrary reports whether /proc/self/maps, at this exact moment,
 * contains a mapping for kLibraryPath — the direct evidence "open"
 * represents, rather than trusting dlopen's return value alone. readOK
 * distinguishes "maps says the library is not mapped" from "maps could not
 * be read at all", which is not evidence of anything. */
static int mapsShowsLibrary(int *readOK) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        if (readOK != NULL) {
            *readOK = 0;
        }
        return 0;
    }
    if (readOK != NULL) {
        *readOK = 1;
    }
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, kLibraryPath)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

int main(void) {
    long starttime = selfStarttime();
    /* Truncate rather than append: each container start is its own run, and
     * a stale log from a previous run would be ground truth for nothing. */
    FILE *truncate = fopen("/var/log/usage.jsonl", "w");
    if (truncate) {
        fclose(truncate);
    }
    char exe[1024];
    ssize_t exeLen = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (exeLen > 0) {
        exe[exeLen] = '\0';
        logEvent(starttime, "exec", exe, 1);
    }

    for (;;) {
        void *h = dlopen(kLibraryPath, RTLD_NOW);
        int ok = h != NULL;
        logEvent(starttime, "dlopen", kLibraryPath, ok);
        if (ok) {
            int readOK = 0;
            int mapped = mapsShowsLibrary(&readOK);
            logEvent(starttime, "open", kLibraryPath, readOK && mapped);
            sleep(7);
            int closeOK = dlclose(h) == 0;
            readOK = 0;
            mapped = mapsShowsLibrary(&readOK);
            logEventExtra(starttime, "dlclose", kLibraryPath, closeOK,
                          "maps_unloaded", (readOK && !mapped) ? "true" : "false");
        }
        sleep(7);
    }
    return 0;
}
