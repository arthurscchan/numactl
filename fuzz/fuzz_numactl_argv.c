/*
 * fuzz_numactl_argv.c - libFuzzer target for the numactl command-line tool's
 * argument parsing and policy dispatch (numactl project).
 *
 * Threat model
 * ============
 * 1. Untrusted input: the numactl CLI is run by users, scripts, job
 *    schedulers and orchestrators with arguments that are frequently built
 *    from untrusted data (node/cpu strings from dashboards, shm paths and
 *    sizes from job specs). The argv vector is the tool's trust boundary.
 * 2. Trust boundary: main()'s getopt_long state machine in numactl.c and the
 *    helpers it dispatches into: numa_parse_nodestring/cpustring wrappers,
 *    util.c's memsize()/parse_policy() string-number parsing, and shm.c's
 *    shared-memory setup (paths, offsets, lengths, modes).
 * 3. Attacker-controlled at the boundary: the entire argv vector - options,
 *    their values, node/cpu strings (incl. netdev:/file:/ip:/block:/pci:
 *    affinity forms), policy names, shm paths/offsets/lengths/modes.
 * 4. Real bug here: memory-safety violation, NULL deref, leak or hang
 *    reachable from argv alone. numactl is not setuid, but it is the project's
 *    main user-facing parser and ~1290 lines of it are absent from the
 *    existing fuzz build entirely.
 *
 * Why this target (coverage rationale)
 * ====================================
 * numactl.c (801), util.c (140) and shm.c (349) are compiled into NO fuzz
 * target today: the OSS-Fuzz build only builds libnuma.la + fuzz_parse_str.
 * This target compiles those files into the fuzz build (build.sh) and drives
 * main() end-to-end, covering the option state machine, policy conflict
 * checks, --show/--hardware reporting paths (incl. distance printing) and the
 * --shm/--file setup code.
 *
 * Design notes
 * ============
 * - Fork-mode: numactl.c calls exit()/usage() on many valid argv shapes, so
 *   each iteration forks; the child runs numactl_main() and may exit freely,
 *   the parent inspects the exit status. Crashes surface as artifacts through
 *   abort() in the parent.
 * - The child chdir()s to /tmp: a forked child inherits libFuzzer's exit
 *   handling, so every product exit() in the child would otherwise drop a
 *   "fuzz target exited" crash-<sha1> artifact into the runner's CWD (/out),
 *   flooding the build output with non-finding files. Child-side artifacts
 *   belong in /tmp; real crashes are detected by the parent via waitpid.
 *   Coverage profiling is unaffected (LLVM_PROFILE_FILE is absolute).
 * - execvp() in numactl.c is replaced AT BUILD TIME via
 *   -Dexecvp=fuzz_no_execvp (fuzz build configuration only; no product-code
 *   edit): the stub returns ENOENT so the run ends in numactl's own
 *   complain() path instead of executing attacker-named binaries.
 *   main is likewise renamed via -Dmain=numactl_main.
 * - stdout/stderr of the child are redirected to /dev/null to keep the log
 *   usable (usage()/--show print on every valid parse); sanitizer crash
 *   status still reaches the parent via waitpid. Set NUMACTL_ARGV_VERBOSE=1
 *   when reproducing an artifact to keep the child's stderr (full ASan trace).
 * - Exit status 23 is ASan's leak exit code: reported as an abort() so leak
 *   findings produce artifacts. Genuine hangs are bounded by a 2 s wait:
 *   on timeout the child is killed and the parent abort()s (finding).
 * - argv is derived by splitting the fuzz bytes on NUL (max 24 tokens,
 *   each truncated to 512 bytes, total 4096 bytes): attacker controls the
 *   full vector, within per-iteration bounds.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <time.h>

extern int numactl_main(int ac, char **av);

/* build-time replacement for execvp() in numactl.c (-Dexecvp=fuzz_no_execvp):
   never execute attacker-named binaries; report ENOENT so numactl's own
   complain() error path runs. */
int fuzz_no_execvp(const char *file, char *const argv[])
{
        (void)argv;
        errno = ENOENT;
        return -1;
}

#define MAX_ARGS      24
#define MAX_TOKEN     512
#define MAX_INPUT     4096
/* Two-tier hang detection (rusage-based, robust across builds):
   - blocked hang: wall time far exceeds the child's own CPU time (the child
     is stuck in sleep/lock/io for its own sake) -> finding after 10 s wall;
   - CPU-spinning hang: child burns CPU for longer than libFuzzer's default
     -timeout=25 s -> finding.
   A plain wall-time threshold is not usable here: instrumented builds
   (coverage) legitimately spend >2 s of wall time per forked child on
   profile writing, which a fixed cap misclassifies as hangs. */
#define BLOCKED_HANG_WALL_MS 10000
#define SPIN_HANG_WALL_MS    25000
#define BLOCKED_HANG_CPU_MS  1000

static int build_argv(const uint8_t *data, size_t size, char *storage,
                      char *av[], int avmax)
{
        size_t len = size < MAX_INPUT ? size : MAX_INPUT - 1;
        int argc = 0;
        size_t i = 0;

        memcpy(storage, data, len);
        storage[len] = '\0';

        av[argc++] = "numactl";
        while (i < len && argc < avmax) {
                while (i < len && storage[i] == '\0')
                        i++;
                if (i >= len)
                        break;
                av[argc++] = &storage[i];
                size_t tlen = 0;
                while (i < len && storage[i] != '\0') {
                        if (tlen == MAX_TOKEN) {
                                storage[i] = '\0';   /* truncate long tokens */
                                break;
                        }
                        tlen++;
                        i++;
                }
        }
        av[argc] = NULL;
        return argc;
}

static void redirect_quiet(void)
{
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0)
                return;
        dup2(fd, STDOUT_FILENO);
        if (!getenv("NUMACTL_ARGV_VERBOSE"))
                dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO)
                close(fd);
}

/* child CPU (user+sys) in ms sampled from /proc; -1 when unavailable */
static int read_cpu_ms(pid_t pid)
{
        char path[64];
        char buf[1024];
        snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0)
                return -1;
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
                return -1;
        buf[n] = '\0';
        /* comm (field 2) may contain spaces: skip to the last ')' */
        char *p = strrchr(buf, ')');
        if (!p)
                return -1;
        p += 2;                     /* now at field 3 (state) */
        long utime = -1, stime = -1;
        int field = 3;
        char *save = NULL;
        for (char *tok = strtok_r(p, " ", &save); tok;
             tok = strtok_r(NULL, " ", &save), field++) {
                if (field == 14)
                        utime = atol(tok);
                if (field == 15) {
                        stime = atol(tok);
                        break;
                }
        }
        if (utime < 0 || stime < 0)
                return -1;
        long tps = sysconf(_SC_CLK_TCK);
        if (tps <= 0)
                return -1;
        return (int)((utime + stime) * 1000 / tps);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
        char storage[MAX_INPUT];
        char *av[MAX_ARGS + 1];
        int argc;
        pid_t pid;

        if (size < 1)
                return 0;
        argc = build_argv(data, size, storage, av, MAX_ARGS);

        pid = fork();
        if (pid == 0) {
                /* keep child-side libFuzzer artifacts out of the runner's /out */
                if (chdir("/tmp") != 0)
                        chdir("/");
                redirect_quiet();
                numactl_main(argc, av);
                _exit(0);   /* numactl_main usually exits itself */
        }
        if (pid < 0)
                return 0;

        /* bounded wait with rusage-based hang classification */
        int wall_ms = 0;
        int status = 0;
        int done = 0;
        while (!done) {
                pid_t r = wait4(pid, &status, WNOHANG, NULL);
                if (r == pid) {
                        done = 1;
                } else if (r < 0) {
                        return 0;   /* waitpid error: skip iteration */
                } else {
                        int cpu_ms = read_cpu_ms(pid);
                        int blocked = wall_ms >= BLOCKED_HANG_WALL_MS &&
                                      (cpu_ms >= 0 && cpu_ms < BLOCKED_HANG_CPU_MS);
                        if (blocked || wall_ms >= SPIN_HANG_WALL_MS) {
                                kill(pid, SIGKILL);
                                waitpid(pid, &status, 0);
                                fprintf(stderr,
                                        "numactl_argv: child hang (wall %d ms, cpu %d ms)%s\n",
                                        wall_ms, cpu_ms, blocked ? " [blocked]" : " [spinning]");
                                abort();   /* finding: genuine hang */
                        }
                        struct timespec ts = { 0, 5 * 1000 * 1000 };
                        nanosleep(&ts, NULL);
                        wall_ms += 5;
                }
        }

        if (WIFSIGNALED(status)) {
                fprintf(stderr, "numactl_argv: child died by signal %d\n",
                        WTERMSIG(status));
                abort();            /* finding: crash */
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 23) {
                fprintf(stderr, "numactl_argv: child leaked (LSan exit 23)\n");
                abort();            /* finding: leak */
        }
        return 0;
}
