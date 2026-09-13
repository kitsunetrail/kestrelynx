/* loader dlopen()s the shared object named on argv[1] and then sleeps
 * indefinitely, keeping that mapping resident in /proc/<pid>/maps for the
 * rest of the observation window regardless of what later happens to the
 * file at that path on disk (unlinked or overwritten). */
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 1;
    }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen %s: %s\n", argv[1], dlerror());
        return 1;
    }
    for (;;) {
        sleep(3600);
    }
    return 0;
}
