/* su.c -- root shell client.
 *
 * Plain `su` asks the sud daemon to fork the shell; sud is the only thing on
 * this device that can (it is started by the rshell channel, which runs as
 * uid 0 with the full capability set).  When sud is not running su falls back
 * to a local setuid exec -- which here is a crippled root: adbd's bounding
 * set is 0xc0 and SECURE_NOROOT is locked, so euid becomes 0 with no
 * capabilities at all.  That path says so instead of pretending.
 *
 *   su                  interactive root shell
 *   su -c 'cmd'         run one command
 *   su -s /path/shell   pick the shell (default: bash if present)
 *   su -d               dump the privilege state the local path is stuck with
 *   su -v               version
 *
 * Flags kept for Magisk compatibility: --mount-master (this build always runs
 * in the global mount namespace, so it is a no-op) and -Z CONTEXT (accepted;
 * this device's policy has no su/magisk domains to transition to, so it warns
 * and continues).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "client.h"
#include "proto.h"

/* bash first: a privileged bash is what was asked for; sh is always there */
static const char *const shells[] = {
    "/data/data/com.termux/files/usr/bin/bash",
    "/system/bin/bash",
    "/system/xbin/bash",
    "/vendor/bin/bash",
    "/data/data/com.termux/files/usr/bin/sh",
    "/system/bin/sh",
    NULL,
};

static bool debug;

static void warn(const char *what)
{
    if (debug)
        fprintf(stderr, "su: %s: %s\n", what, strerror(errno));
}

static const char *basename_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static const char *pick_shell(void)
{
    for (int i = 0; shells[i]; i++)
        if (access(shells[i], X_OK) == 0)
            return shells[i];
    return "/system/bin/sh";
}

/* no libcap on the device: two raw syscalls and the uapi structs.
 * Raising *effective* to the already-permitted set needs no privilege. */
static bool cap_raise_effective(void)
{
    struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct d[2];
    bool changed = false;

    if (syscall(SYS_capget, &hdr, d) != 0) {
        warn("capget");
        return false;
    }
    for (int i = 0; i < 2; i++) {
        uint32_t want = d[i].effective | d[i].permitted;
        if (want != d[i].effective) {
            d[i].effective = want;
            changed = true;
        }
    }
    if (changed && syscall(SYS_capset, &hdr, d) != 0) {
        warn("capset");
        return false;
    }
    return changed;
}

static void dump_state(void)
{
    FILE *f;
    char line[256];
    int sb = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);

    fprintf(stderr, "su: securebits=0x%x%s\n", sb,
            (sb & SECBIT_NOROOT) ? "  <- SECURE_NOROOT: root is not special" : "");
    f = fopen("/proc/self/status", "re");
    if (!f) return;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4) ||
            !strncmp(line, "Cap", 3))
            fprintf(stderr, "su:   %s", line);
    fclose(f);
}

/* --- the daemon path ----------------------------------------------------- */

static char *build_env(size_t *out_len)
{
    extern char **environ;
    size_t n = 0;
    char *buf, *p;

    for (char **e = environ; *e; e++) n += strlen(*e) + 1;
    buf = calloc(1, n + 1);
    if (!buf) {
        *out_len = 0;
        return NULL;
    }
    p = buf;
    for (char **e = environ; *e; e++) {
        size_t l = strlen(*e) + 1;
        memcpy(p, *e, l);
        p += l;
    }
    *out_len = n;
    return buf;
}

/* fd i if it is open, else /dev/null, so the daemon always gets three */
static int stdio_fd(int i)
{
    if (fcntl(i, F_GETFD) >= 0) return i;
    return open("/dev/null", O_RDWR);
}

/* returns the shell's exit status, or -1 if the daemon is not reachable */
static int run_via_daemon(const char *shell, const char *cmd)
{
    size_t envlen = 0;
    char *env = build_env(&envlen);
    const char *c = cmd ? cmd : "";
    struct su_req req;
    struct su_reply rep;
    char *text = NULL, *payload;
    int fds[3], fd, rc;
    size_t off = 0;

    fd = su_connect(SU_SOCKET);
    if (fd < 0) {
        free(env);
        return -1;
    }

    memset(&req, 0, sizeof req);
    req.magic = SU_MAGIC;
    req.op = SU_OP_RUN;
    /* envlen, not strlen(env): the env blob is NUL-separated, so
     * strlen would stop at the first variable and under-allocate */
    req.len = (uint32_t)(strlen(shell) + 1 + strlen(c) + 1 + envlen);
    payload = calloc(1, req.len + 4);           /* slack for NUL splits */
    if (!payload) {
        close(fd);
        free(env);
        return -1;
    }
    memcpy(payload + off, shell, strlen(shell) + 1);
    off += strlen(shell) + 1;
    memcpy(payload + off, c, strlen(c) + 1);
    off += strlen(c) + 1;
    if (envlen) memcpy(payload + off, env, envlen);

    for (int i = 0; i < 3; i++) fds[i] = stdio_fd(i);
    rc = su_call(fd, &req, payload, fds, &rep, &text);
    for (int i = 0; i < 3; i++)
        if (fds[i] > 2) close(fds[i]);
    close(fd);
    free(payload);
    free(env);

    if (rc < 0) {
        fprintf(stderr, "su: sud closed the connection\n");
        return 1;
    }
    if (text) {
        fputs(text, stderr);
        free(text);
    }
    return rep.rc;
}

/* --- the local (setuid) fallback ---------------------------------------- */

static int run_local(const char *shell, const char *cmd)
{
    char *args[4];

    if (geteuid() != 0) {
        fprintf(stderr,
                "su: sud is not running and this su has no setuid bit\n"
                "    (euid=%d).  Bring the daemon up once per boot with\n"
                "      tools/su/install.sh\n",
                (int)geteuid());
        return 1;
    }
    cap_raise_effective();
    setgroups(0, NULL);
    setgid(0);
    setuid(0);

    if (debug)
        dump_state();
    else if (getegid() != 0)
        fprintf(stderr, "su: warning: limited root -- uid=%d gid=%d, no "
                        "capabilities (run su -d for the detail)\n",
                (int)geteuid(), (int)getegid());

    setenv("HOME", "/", 1);
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    setenv("SHELL", shell, 1);
    setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin", 1);

    args[0] = (char *)basename_of(shell);
    if (cmd && *cmd) {
        args[1] = "-c";
        args[2] = (char *)cmd;
        args[3] = NULL;
    } else {
        args[1] = "-i";
        args[2] = NULL;
    }
    execv(shell, args);
    fprintf(stderr, "su: execv %s: %s\n", shell, strerror(errno));
    return 126;
}

static void usage(void)
{
    fputs("usage: su [-d] [-c cmd] [-s shell] [-Z context] [--mount-master] [root]\n",
          stderr);
}

int main(int argc, char **argv)
{
    const char *cmd = NULL, *shell = NULL, *context = NULL;
    int rc;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-c") && i + 1 < argc) cmd = argv[++i];
        else if (!strcmp(a, "-s") && i + 1 < argc) shell = argv[++i];
        else if (!strcmp(a, "-Z") && i + 1 < argc) context = argv[++i];
        else if (!strcmp(a, "--mount-master")) continue;    /* always global here */
        else if (!strcmp(a, "-d")) debug = true;
        else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("su %s (sud client)\n", SU_VERSION);
            return 0;
        }
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage();
            return 0;
        }
        else if (!strcmp(a, "--") || !strcmp(a, "-")) continue;
        else if (!strcmp(a, "root") || !strcmp(a, "0")) continue;
        else {
            fprintf(stderr, "su: unknown argument: %s\n", a);
            usage();
            return 2;
        }
    }
    debug = debug || getenv("SU_DEBUG") != NULL;

    if (context)
        fprintf(stderr, "su: -Z %s ignored: this device's policy has no other "
                        "su domain to transition to\n", context);
    if (!shell) shell = getenv("SU_SHELL");
    if (shell && access(shell, X_OK) != 0) {
        fprintf(stderr, "su: %s: %s\n", shell, strerror(errno));
        return 126;
    }
    if (!shell) shell = pick_shell();

    rc = run_via_daemon(shell, cmd);
    if (rc >= 0) {
        /* the daemon had the caller's tty in raw mode while the shell ran;
         * nudge our shell to redraw its prompt (Magisk does the same) */
        if (isatty(0)) raise(SIGWINCH);
        return rc;
    }
    return run_local(shell, cmd);
}
