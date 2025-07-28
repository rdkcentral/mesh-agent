#include "xmesh_diag.h"

/**
* Signal hanler added so that if user sends SIGINT, xmesh_diag_stop() would have time to print the stats instead of
* the process dying immediately.
*/
void sig_handler(int signum) {
    printf("xmesh_diagnostics: received signal %d\n", signum);
}

void usage() {
    printf("Usage:\n");
    printf("xmesh_diagnostics [-d][-w][-l]\n");
    printf("    -d: enable dumps\n");
    printf("    -w: set this when device is in wfo mode\n");
    printf("    -l: enable printing logs in /rdklogs/logs/MeshBlackbox.log\n");
}

int main(int argc, char **argv) {

    LOG_TO_CONSOLE(true);
    LOG_TO_FILE(false);
    signal(SIGINT, sig_handler);

    int opt;
    bool dumps_enabled = false;
    bool wfo = false;

    while ((opt = getopt(argc, argv, ":dwl")) != -1) {
        switch(opt) {
            case 'd': dumps_enabled = true;
                      break;
            case 'w': wfo = true;
                      break;
            case 'l': LOG_TO_FILE(true);
                      break;
            case '?': printf("Unknown argument %c\n",optopt);
                      usage();
                      return -1;
        }
    }

    xmesh_diag_start(5, dumps_enabled, wfo, 0);
    // sleep to ensure xmesh_diag_stop() won't run before thread even starts.
    // TODO replace later with pthread_cond_wait and signal
    sleep(2);
    xmesh_diag_stop();
    return 0;
}
