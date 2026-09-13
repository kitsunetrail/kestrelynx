/* sleeper stands in for a long-running server binary ("server-a"): it does
 * nothing but stay resident, so its own exe path can be unlinked out from
 * under it while it keeps running. */
#include <unistd.h>

int main(void) {
    for (;;) {
        sleep(3600);
    }
    return 0;
}
