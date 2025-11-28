/**
 * LD_PRELOAD errno interceptor v2
 * Author: Claude
 * Purpose: Hook errno only in child process, avoid duplicates
 * Created: 2025-11-22
 * Expected: Capture only the 28 validation errno values
 * Result: (to be filled after run)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>

static FILE *logfile = NULL;
static int last_errno = -999;
static pid_t child_pid = 0;
static int is_child = 0;

// Constructor to detect if we're in child process
__attribute__((constructor)) void detect_process() {
    // After fork, child will have different PID
    // We detect child by checking if ptrace(PTRACE_TRACEME) succeeds
    // But that interferes with the binary's anti-debug, so we'll use PID comparison
    // The child is created after the binary starts
}

pid_t fork(void) {
    static pid_t (*real_fork)(void) = NULL;
    if (!real_fork) {
        real_fork = dlsym(RTLD_NEXT, "fork");
    }

    pid_t result = real_fork();
    if (result == 0) {
        // We are in the child process
        is_child = 1;
        if (!logfile) {
            logfile = fopen("/tmp/errno_log_v2.txt", "w");
            setvbuf(logfile, NULL, _IONBF, 0);
        }
        fprintf(logfile, "=== CHILD PROCESS START ===\n");
        fflush(logfile);
    }
    return result;
}

// Hook __errno_location to track errno reads only in child
int *__errno_location(void) {
    static int *(*real_errno)(void) = NULL;
    static int read_count = 0;

    if (!real_errno) {
        real_errno = dlsym(RTLD_NEXT, "__errno_location");
    }

    int *ptr = real_errno();

    // Only log in child process
    if (is_child && ptr && *ptr != 0 && *ptr != last_errno) {
        if (!logfile) {
            logfile = fopen("/tmp/errno_log_v2.txt", "w");
            setvbuf(logfile, NULL, _IONBF, 0);
        }
        fprintf(logfile, "[%d] errno = %d\n", read_count++, *ptr);
        fflush(logfile);
        last_errno = *ptr;
    }

    return ptr;
}
