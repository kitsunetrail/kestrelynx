/* Minimal dynamically-linked HTTP server for case 6: it exists
 * only to be a long-running process that genuinely links glibc (no static
 * linking, no CGO-style avoidance of it), so that a distroless/cc-debian12
 * base's dynamic libraries appear as executable, file-backed mappings.
 * It answers every connection with a fixed "ok" response.
 *
 * It also writes the ground-truth usage log every self-built test image in
 * this matrix writes, /var/log/usage.jsonl, one JSON object per line:
 *
 *   {"ts":"<RFC3339Nano>","pid":<int>,"starttime":<int>,
 *    "event":"exec"|"open","path":"<absolute path>","ok":true|false}
 *
 * "open" events are generated from /proc/self/maps snapshots: one right
 * after startup and one every SNAPSHOT_INTERVAL_SECONDS after that, so a
 * sampling window that starts later still finds in-window positives. A
 * maps snapshot is a point-in-time record of what is loaded, which is
 * exactly what an "open" event means here. The periodic snapshot is driven
 * by SIGALRM interrupting accept(): a flag is set in the handler and the
 * writing itself happens back in the main loop, so no non-async-signal-safe
 * function ever runs inside the handler. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LOG_PATH "/var/log/usage.jsonl"
#define SNAPSHOT_INTERVAL_SECONDS 5

static volatile sig_atomic_t snapshotDue = 0;

static void onAlarm(int sig) {
    (void)sig;
    snapshotDue = 1;
}

/* selfStarttime returns field 22 (starttime) of /proc/self/stat. Field 2
 * (comm) is parenthesized and may itself contain ')', so parsing starts
 * after the *last* ')'. */
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

static void logEvent(long starttime, const char *event, const char *path, int ok) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return;
    }
    struct tm tmv;
    gmtime_r(&ts.tv_sec, &tmv);
    char stamp[40];
    strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tmv);

    FILE *f = fopen(LOG_PATH, "a");
    if (!f) {
        return;
    }
    fprintf(f, "{\"ts\":\"%s.%09ldZ\",\"pid\":%d,\"starttime\":%ld,\"event\":\"%s\",\"path\":\"%s\",\"ok\":%s}\n",
            stamp, (long)ts.tv_nsec, (int)getpid(), starttime, event, path, ok ? "true" : "false");
    fclose(f);
}

/* snapshot writes one "open" event per executable, file-backed mapping
 * currently in /proc/self/maps — the same selection the collector makes
 * from the outside, so ground truth and observation describe the same set.
 * Duplicate paths within one snapshot are collapsed by only emitting a
 * path when it differs from the previous line's path, which is enough:
 * the kernel lists a file's segments consecutively. */
static void snapshot(long starttime) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        return;
    }
    char line[4096];
    char previous[1024];
    previous[0] = '\0';
    while (fgets(line, sizeof(line), f)) {
        char perms[8], dev[16], pathname[1024];
        unsigned long long start, end, offset, inode;
        pathname[0] = '\0';
        int matched = sscanf(line, "%llx-%llx %7s %llx %15s %llu %1023[^\n]",
                             &start, &end, perms, &offset, dev, &inode, pathname);
        if (matched < 7 || inode == 0) {
            continue;
        }
        if (strlen(perms) < 3 || perms[2] != 'x') {
            continue;
        }
        char *p = pathname;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (p[0] != '/') {
            continue;
        }
        char *deleted = strstr(p, " (deleted)");
        if (deleted) {
            *deleted = '\0';
        }
        if (strcmp(p, previous) == 0) {
            continue;
        }
        snprintf(previous, sizeof(previous), "%s", p);
        logEvent(starttime, "open", p, 1);
    }
    fclose(f);
}

int main(void) {
    long starttime = selfStarttime();
    /* Truncate rather than append: each container start is its own run, and
     * a stale log from a previous run would be ground truth for nothing. */
    FILE *truncate = fopen(LOG_PATH, "w");
    if (truncate) {
        fclose(truncate);
    }

    char exe[1024];
    ssize_t exeLen = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (exeLen > 0) {
        exe[exeLen] = '\0';
        logEvent(starttime, "exec", exe, 1);
    }
    snapshot(starttime);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = onAlarm;
    /* No SA_RESTART: accept() must return EINTR so the main loop can notice
     * that a snapshot is due. */
    sigaction(SIGALRM, &sa, NULL);
    alarm(SNAPSHOT_INTERVAL_SECONDS);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        return 1;
    }
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8080);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        return 1;
    }
    if (listen(srv, 16) != 0) {
        return 1;
    }

    const char *resp = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
    for (;;) {
        if (snapshotDue) {
            snapshotDue = 0;
            snapshot(starttime);
            alarm(SNAPSHOT_INTERVAL_SECONDS);
        }
        int c = accept(srv, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) {
                continue; /* a snapshot came due; handled at the top of the loop */
            }
            continue;
        }
        char buf[512];
        ssize_t n = read(c, buf, sizeof(buf));
        (void)n; /* the request itself is not parsed: any input is answered the same way */
        ssize_t w = write(c, resp, strlen(resp));
        (void)w;
        close(c);
    }
    return 0;
}
