/* sud.c -- permission-based root daemon: the half of su that holds the
 * privilege.  See README.md for why the privilege has to live in a daemon
 * on this device (SECURE_NOROOT + a 0xc0 bounding set: a setuid binary gets
 * euid 0 and nothing else).
 *
 *   sud            daemonize; policy in $SU_DIR/su.policies, log in $SU_DIR/sud.log
 *   sud -f         stay in the foreground (debugging)
 *   sud -n         first run: do not pre-allow the shell uid
 *
 * Model, as every su since SuperSU has had it:
 *   - each uid has a policy: deny / allow / ask   (Magisk's numbering)
 *   - unknown uid => ask: queue the request, launch the manager app's prompt
 *   - a decision is written back as a policy with an optional expiry
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "framing.h"
#include "policy.h"
#include "proto.h"

#define PROMPT_TIMEOUT_MS 120000        /* how long a request waits for the user */
#define LOG_TAIL          50
#define MAX_POLICIES      128

static int   logfd = -1;
static bool  foreground;

/* --- small helpers ------------------------------------------------------- */

static void write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;
        }
        p += n;
        len -= n;
    }
}

static void logmsg(const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    time_t now = time(NULL);
    struct tm tm;
    int n;

    localtime_r(&now, &tm);
    n = snprintf(line, sizeof line, "%04d-%02d-%02d %02d:%02d:%02d ",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof line - n, fmt, ap);
    va_end(ap);
    if (n > (int)sizeof line - 2) n = sizeof line - 2;
    line[n++] = '\n';
    write_all(logfd, line, n);
    if (foreground) write_all(2, line, n);
}

static int read_file(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t n = 0;
    if (fd < 0) return -1;
    while (n < cap - 1) {
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r <= 0) break;
        n += r;
    }
    close(fd);
    buf[n] = 0;
    return (int)n;
}

static void set_owner(const char *path, uid_t uid, gid_t gid, mode_t mode)
{
    chown(path, uid, gid);
    chmod(path, mode);
}

/* --- policies ------------------------------------------------------------ */

static int load_policies(struct su_pol *v, int max)
{
    FILE *f = fopen(su_cfg.policies, "re");
    char line[512];
    int n = 0;

    if (!f) return 0;
    while (n < max && fgets(line, sizeof line, f)) {
        if (su_parse_policy_line(line, &v[n]) == 0) n++;
    }
    fclose(f);
    return n;
}

/* last matching line wins; an expired entry means "ask again" */
static int policy_for(uid_t uid, int64_t *until)
{
    struct su_pol v[MAX_POLICIES];
    int n = load_policies(v, MAX_POLICIES);
    int found = SU_POLICY_ASK;
    int64_t fu = 0;

    for (int i = 0; i < n; i++) {
        if (v[i].uid == uid) {
            found = v[i].policy;
            fu = v[i].until;
        }
    }
    if (until) *until = fu;
    if (found != SU_POLICY_ASK && fu != 0 && fu < (int64_t)time(NULL))
        found = SU_POLICY_ASK;                  /* grant expired */
    return found;
}

static int policy_set(uid_t uid, int policy, int64_t until)
{
    char tmp[512], line[512], newline[512];
    FILE *in = fopen(su_cfg.policies, "re");
    FILE *out;
    bool done = false;

    /* same directory, so the rename below is atomic */
    snprintf(tmp, sizeof tmp, "%s.tmp", su_cfg.policies);
    out = fopen(tmp, "we");
    if (!out) {
        if (in) fclose(in);
        return -1;
    }
    while (in && fgets(line, sizeof line, in)) {
        struct su_pol e;
        if (su_parse_policy_line(line, &e) == 0 && e.uid == uid) {
            if (!done &&
                su_format_policy_line(newline, sizeof newline, uid, policy, until) > 0) {
                fputs(newline, out);
                done = true;
            }
            continue;                           /* drop duplicate lines */
        }
        fputs(line, out);
    }
    if (in) fclose(in);
    if (!done &&
        su_format_policy_line(newline, sizeof newline, uid, policy, until) > 0)
        fputs(newline, out);
    if (fclose(out) != 0) return -1;
    set_owner(tmp, 0, SU_UID_SHELL, 0660);
    return rename(tmp, su_cfg.policies);
}

/* --- pending requests ---------------------------------------------------- */

static bool pending_contains(uid_t uid)
{
    FILE *f = fopen(su_cfg.pending, "re");
    char line[128];
    bool found = false;

    while (f && fgets(line, sizeof line, f)) {
        long long u;
        if (sscanf(line, "%lld", &u) == 1 && (uid_t)u == uid) {
            found = true;
            break;
        }
    }
    if (f) fclose(f);
    return found;
}

static void pending_add(uid_t uid)
{
    FILE *f = fopen(su_cfg.pending, "ae");

    if (!f) return;
    fprintf(f, "%u %lld\n", uid, (long long)time(NULL));
    fclose(f);
    set_owner(su_cfg.pending, 0, SU_UID_SHELL, 0660);
}

static void pending_remove(uid_t uid)
{
    char tmp[512];
    FILE *in = fopen(su_cfg.pending, "re");
    FILE *out;
    char line[128];

    snprintf(tmp, sizeof tmp, "%s.tmp", su_cfg.pending);
    out = fopen(tmp, "we");
    if (!out) {
        if (in) fclose(in);
        return;
    }
    while (in && fgets(line, sizeof line, in)) {
        long long u;
        if (sscanf(line, "%lld", &u) == 1 && (uid_t)u == uid) continue;
        fputs(line, out);
    }
    if (in) fclose(in);
    if (fclose(out) != 0) return;
    set_owner(tmp, 0, SU_UID_SHELL, 0660);
    rename(tmp, su_cfg.pending);
}

/* --- uid <-> package, from the platform's own list ----------------------- */

/* first uid holding one of the manager packages, or -1 */
static uid_t pkg_uid(const char *want)
{
    FILE *f = fopen("/data/system/packages.list", "re");
    char line[512];
    uid_t uid = (uid_t)-1;

    while (f && fgets(line, sizeof line, f)) {
        char name[256];
        long u;
        if (sscanf(line, "%255s %ld", name, &u) == 2 && !strcmp(name, want)) {
            uid = (uid_t)u;
            break;
        }
    }
    if (f) fclose(f);
    return uid;
}

static void pkg_for_uid(uid_t uid, char *out, size_t cap)
{
    FILE *f = fopen("/data/system/packages.list", "re");
    char line[512];

    out[0] = 0;
    while (f && fgets(line, sizeof line, f)) {
        char name[256];
        long u;
        if (sscanf(line, "%255s %ld", name, &u) == 2 && (uid_t)u == uid) {
            snprintf(out, cap, "%s", name);
            break;
        }
    }
    if (f) fclose(f);
}

static uid_t manager_uid(void)
{
    uid_t u = pkg_uid(su_cfg.manager_pkg);

    return u != (uid_t)-1 ? u : pkg_uid(su_cfg.shell_pkg);
}

static bool is_manager(uid_t uid)
{
    if (uid == 0 || uid == SU_UID_SHELL) return true;
    if (uid == (uid_t)-1) return false;
    return uid == pkg_uid(su_cfg.manager_pkg) || uid == pkg_uid(su_cfg.shell_pkg);
}

/* --- the prompt ---------------------------------------------------------- */

static void launch_manager(void)
{
    pid_t pid = fork();

    if (pid != 0) return;
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
    }
    execl("/system/bin/am", "am", "start", "-n", su_cfg.request_act, NULL);
    _exit(127);
}

/* ask the user: returns the decided policy */
static int ask(uid_t uid)
{
    if (manager_uid() == (uid_t)-1) {
        logmsg("ASK uid=%u manager app %s is not installed", uid, su_cfg.manager_pkg);
        return SU_POLICY_DENY;
    }
    if (!pending_contains(uid)) {
        pending_add(uid);
        logmsg("ASK uid=%u prompting via %s", uid, su_cfg.manager_pkg);
        launch_manager();
    }
    for (int i = 0; i < PROMPT_TIMEOUT_MS / 250; i++) {
        int p = policy_for(uid, NULL);
        if (p != SU_POLICY_ASK) {
            pending_remove(uid);
            logmsg("ASK uid=%u answered: %s", uid, su_policy_name(p));
            return p;
        }
        usleep(250000);
    }
    pending_remove(uid);
    logmsg("ASK uid=%u timed out after %ds", uid, PROMPT_TIMEOUT_MS / 1000);
    return SU_POLICY_DENY;
}

/* --- running the shell --------------------------------------------------- */

static void exec_shell(const char *shell, const char *cmd)
{
    const char *base = strrchr(shell, '/');
    char args0[64];
    char *args[4];

    base = base ? base + 1 : shell;
    snprintf(args0, sizeof args0, "%s", base);
    setenv("SHELL", shell, 1);
    args[0] = args0;
    if (cmd && *cmd) {
        args[1] = "-c";
        args[2] = (char *)cmd;
        args[3] = NULL;
    } else {
        args[1] = "-i";
        args[2] = NULL;
    }
    execv(shell, args);
}

static void apply_env(char *env)
{
    for (char *e = env; e && *e; e = strchr(e, '\0') + 1)
        putenv(e);
}

/* --- the shell's own pty -------------------------------------------------
 * The shell runs on a fresh pty and this process pumps the caller's stdio
 * through it (Magisk's design, native/src/core/su/pts.rs).  Stealing the
 * caller's controlling terminal would work but leaves the calling shell
 * unable to tcsetpgrp() afterwards. */

#define TIOCGPTN  0x80045430            /* _IOR(T,0x30) get pty number */
#define TIOCSPTLCK 0x40045431           /* _IOW(T,0x31) lock/unlock slave */

static int open_pty(char *slave, size_t cap, const struct winsize *ws)
{
    int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
    unsigned int n = 0;

    if (ptmx < 0) return -1;
    if (ioctl(ptmx, TIOCGPTN, &n) != 0) {
        close(ptmx);
        return -1;
    }
    snprintf(slave, cap, "/dev/pts/%u", n);
    /* devpts hands out *locked* slaves: an open() before this gets EIO
     * (drivers/tty/pty.c TIOCSPTLCK) */
    {
        int zero = 0;
        if (ioctl(ptmx, TIOCSPTLCK, &zero) != 0) {
            close(ptmx);
            return -1;
        }
    }
    if (ws) ioctl(ptmx, TIOCSWINSZ, ws);
    return ptmx;
}

/* Forward bytes both ways until the shell is *and* the pty is done.  A fast
 * command (su -c true) exits before its output has been read, so reaping the
 * child must not short-circuit the drain. */
static void pump_pty(int ptmx, int in, int out, pid_t child, int *status,
                     bool *reaped)
{
    char buf[4096];
    bool watch_in = true, done = false;

    for (;;) {
        struct pollfd pfd[2] = {
            { ptmx, POLLIN, 0 },
            { watch_in ? in : -1, POLLIN, 0 },
        };
        int n = poll(pfd, 2, 200);

        if (n < 0 && errno != EINTR) break;
        if (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t r = read(ptmx, buf, sizeof buf);
            if (r > 0) {
                write_all(out, buf, (size_t)r);
                continue;
            }
            if (r == 0 || errno == EIO) break;      /* shell side is gone */
        }
        if (watch_in && (pfd[1].revents & (POLLIN | POLLHUP))) {
            ssize_t r = read(in, buf, sizeof buf);
            if (r > 0) write_all(ptmx, buf, (size_t)r);
            else watch_in = false;                  /* caller hung up */
        }
        if (!done && waitpid(child, status, WNOHANG) == child) {
            done = true;
            *reaped = true;
        }
        if (done) {                                 /* drain, then stop */
            struct pollfd d = { ptmx, POLLIN, 0 };
            if (poll(&d, 1, 0) <= 0 || !(d.revents & POLLIN)) break;
        }
    }
}

static int run_shell(uid_t peer, char *shell, char *cmd, char *env, int *fds)
{
    struct termios saved;
    struct winsize ws;
    char slave[64] = "";
    bool has_tty = isatty(fds[0]) != 0;
    bool raw = false;
    int ptmx = -1, st = 0, rc;
    bool reaped = false;
    pid_t pid;

    if (!shell[0] || shell[0] != '/' || access(shell, X_OK) != 0)
        shell = "/system/bin/sh";

    if (has_tty) {
        if (ioctl(fds[0], TIOCGWINSZ, &ws) != 0) memset(&ws, 0, sizeof ws);
        ptmx = open_pty(slave, sizeof slave, &ws);
        if (ptmx < 0) {
            has_tty = false;                    /* plain fds then */
        } else if (tcgetattr(fds[0], &saved) == 0) {
            struct termios r = saved;
            cfmakeraw(&r);                      /* the slave does the editing */
            if (tcsetattr(fds[0], TCSANOW, &r) == 0)
                raw = true;
        }
    }

    pid = fork();
    if (pid == 0) {
        /* diagnostics must go to the caller's stderr: once the slave is
         * dup2'd over fd 2 they would land on the pty instead */
        int cerr = fds[2];

        signal(SIGCHLD, SIG_DFL);
        setsid();
        if (ptmx >= 0) close(ptmx);
        if (has_tty) {
            int s = open(slave, O_RDWR | O_NOCTTY);
            if (s < 0) {
                dprintf(cerr, "sud: open %s: %s\n", slave, strerror(errno));
                _exit(121);
            }
            if (ioctl(s, TIOCSCTTY, 0) != 0)
                dprintf(cerr, "sud: TIOCSCTTY %s: %s\n", slave, strerror(errno));
            fds[0] = fds[1] = fds[2] = s;
        }
        for (int i = 0; i < 3; i++) {
            if (fds[i] < 0) {
                dprintf(cerr, "sud: bad fd %d\n", i);
                _exit(122);
            }
        }
        dup2(fds[0], 0);
        dup2(fds[1], 1);
        dup2(fds[2], 2);
        for (int i = 0; i < 3; i++)
            if (fds[i] > 2) close(fds[i]);

        if (geteuid() != 0) {
            dprintf(cerr, "sud: not root (euid=%d)\n", (int)geteuid());
            _exit(123);
        }
        setgroups(0, NULL);
        setgid(0);
        setuid(0);
        apply_env(env);
        setenv("HOME", "/", 1);
        setenv("USER", "root", 1);
        setenv("LOGNAME", "root", 1);
        setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin", 1);
        chdir("/");
        exec_shell(shell, cmd);
        dprintf(cerr, "sud: execv %s: %s\n", shell, strerror(errno));
        _exit(126);
    }
    if (pid < 0) {
        if (ptmx >= 0) close(ptmx);
        if (raw) tcsetattr(fds[0], TCSANOW, &saved);
        return -1;
    }

    if (has_tty) pump_pty(ptmx, fds[0], fds[1], pid, &st, &reaped);
    if (!reaped) waitpid(pid, &st, 0);
    if (ptmx >= 0) close(ptmx);
    if (raw) tcsetattr(fds[0], TCSANOW, &saved);   /* hand the tty back as found */

    rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
    logmsg("RUN uid=%u pid=%d rc=%d cmd=\"%s\"", peer, pid, rc, cmd);
    return rc;
}

/* --- replies ------------------------------------------------------------- */

static void reply(int conn, int32_t rc, const char *text)
{
    su_send_reply(conn, rc, text);
}

/* --- connection handling ------------------------------------------------- */

struct buf {
    char  *p;
    size_t len, cap;
};

static void buf_add(struct buf *b, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (b->len + 1 >= b->cap) return;
    va_start(ap, fmt);
    n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n > 0) b->len += (size_t)n;
}

static char *list_text(void)
{
    struct su_pol v[MAX_POLICIES];
    int n = load_policies(v, MAX_POLICIES);
    struct buf b = { malloc(8192), 0, 8192 };

    if (!b.p) return NULL;
    b.p[0] = 0;
    if (n == 0) buf_add(&b, "(no policies)\n");
    for (int i = 0; i < n; i++) {
        char pkg[256];
        pkg_for_uid(v[i].uid, pkg, sizeof pkg);
        buf_add(&b, "%-6u %-5s %-12lld %s\n", v[i].uid, su_policy_name(v[i].policy),
                (long long)v[i].until, pkg[0] ? pkg : "");
    }
    return b.p;
}

static char *pending_text(void)
{
    FILE *f = fopen(su_cfg.pending, "re");
    struct buf b = { malloc(4096), 0, 4096 };
    char line[128];

    if (!b.p) {
        if (f) fclose(f);
        return NULL;
    }
    b.p[0] = 0;
    while (f && fgets(line, sizeof line, f)) {
        char pkg[256];
        long long u;
        if (sscanf(line, "%lld", &u) != 1) continue;
        pkg_for_uid((uid_t)u, pkg, sizeof pkg);
        buf_add(&b, "%lld %s\n", u, pkg[0] ? pkg : "(unknown)");
    }
    if (f) fclose(f);
    if (!b.p[0]) buf_add(&b, "(nothing pending)\n");
    return b.p;
}

static char *log_text(void)
{
    static char buf[65536];
    static char *starts[4096];
    int n = 0, first;
    int rc = read_file(su_cfg.log, buf, sizeof buf);
    size_t len;

    if (rc <= 0) return strdup("(no log yet)\n");
    len = (size_t)rc;
    for (size_t i = 0; i < len && n < 4096; i++)
        if (i == 0 || buf[i - 1] == '\n')
            starts[n++] = buf + i;
    first = n > LOG_TAIL ? n - LOG_TAIL : 0;
    if (first >= n) return strdup("(no log yet)\n");
    return strndup(starts[first], len - (size_t)(starts[first] - buf));
}

static void handle(int conn, uid_t peer)
{
    struct su_req r;
    int fds[3] = { -1, -1, -1 };
    char *payload = NULL;

    if (su_recv_request(conn, &r, &payload, fds) != 0) {
        logmsg("dropping malformed request from uid=%u", peer);
        return;
    }

    switch (r.op) {
    case SU_OP_RUN: {
        char *shell, *cmd, *env, *end = payload + r.len;
        int pol;

        /* the payload is shell\0cmd\0env...: every boundary below is checked
         * against `end` so a truncated one cannot read past the buffer */
        if (!payload || !memchr(payload, 0, r.len)) {
            reply(conn, 1, "malformed RUN payload\n");
            break;
        }
        shell = payload;
        cmd = shell + strlen(shell) + 1;
        if (cmd > end) { reply(conn, 1, "malformed RUN payload\n"); break; }
        env = cmd + strlen(cmd) + 1;
        if (env > end) { reply(conn, 1, "malformed RUN payload\n"); break; }

        pol = peer == 0 ? SU_POLICY_ALLOW : policy_for(peer, NULL);
        if (pol == SU_POLICY_ASK) pol = ask(peer);
        if (pol != SU_POLICY_ALLOW) {
            char pkg[256];
            pkg_for_uid(peer, pkg, sizeof pkg);
            logmsg("DENY uid=%u (%s) cmd=\"%s\"", peer, pkg[0] ? pkg : "?", cmd);
            reply(conn, 1, "denied by policy -- grant with: sumgr allow <uid>\n");
            break;
        }
        if (fds[0] < 0 || fds[1] < 0 || fds[2] < 0) {
            reply(conn, 1, "no stdio fds in request\n");
            break;
        }
        reply(conn, run_shell(peer, shell, cmd, env, fds), NULL);
        break;
    }
    case SU_OP_LIST:
    case SU_OP_PENDING:
    case SU_OP_LOG:
    case SU_OP_SET:
    case SU_OP_STOP: {
        char *text = NULL;
        if (!is_manager(peer)) {
            logmsg("REFUSE manager op %u from untrusted uid=%u", r.op, peer);
            reply(conn, 1, "not allowed to manage policies\n");
            break;
        }
        switch (r.op) {
        case SU_OP_LIST:
            text = list_text();
            reply(conn, 0, text ? text : "(out of memory)\n");
            break;
        case SU_OP_PENDING:
            text = pending_text();
            reply(conn, 0, text ? text : "(out of memory)\n");
            break;
        case SU_OP_LOG:
            text = log_text();
            reply(conn, 0, text ? text : "(out of memory)\n");
            break;
        case SU_OP_SET: {
            int rc;
            if (r.policy != SU_POLICY_DENY && r.policy != SU_POLICY_ALLOW &&
                r.policy != SU_POLICY_ASK) {
                reply(conn, 1, "bad policy\n");
                break;
            }
            rc = policy_set((uid_t)r.uid, (int)r.policy, r.until);
            if (rc == 0) {
                pending_remove((uid_t)r.uid);
                logmsg("SET uid=%u %s until=%lld by uid=%u", r.uid,
                       su_policy_name((int)r.policy), (long long)r.until, peer);
            }
            reply(conn, rc == 0 ? 0 : 1, rc == 0 ? NULL : "cannot write policy\n");
            break;
        }
        case SU_OP_STOP:
            reply(conn, 0, "stopping\n");
            logmsg("STOP requested by uid=%u", peer);
            /* this handler is a forked child; the daemon is its parent */
            kill(getppid(), SIGTERM);
            break;
        }
        free(text);
        break;
    }
    default:
        logmsg("unknown op %u from uid=%u", r.op, peer);
        reply(conn, 1, "unknown op\n");
        break;
    }

    for (int i = 0; i < 3; i++)
        if (fds[i] >= 0) close(fds[i]);
    free(payload);
}

/* --- daemon plumbing ----------------------------------------------------- */

static int listen_socket(void)
{
    struct sockaddr_un addr;
    int fd;

    unlink(su_cfg.sock);
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (strlen(su_cfg.sock) >= sizeof addr.sun_path) {
        logmsg("FATAL: socket path too long: %s", su_cfg.sock);
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, su_cfg.sock, strlen(su_cfg.sock));
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        logmsg("bind %s: %s", su_cfg.sock, strerror(errno));
        return -1;
    }
    if (listen(fd, 8) != 0) return -1;
    /* world-connectable; authorization is the peer uid, not the path */
    chmod(su_cfg.sock, 0666);
    return fd;
}

static void daemonize(void)
{
    pid_t pid = fork();

    if (pid < 0) exit(1);
    if (pid > 0) _exit(0);              /* the channel gets its prompt return */
    setsid();
    umask(0077);
    chdir("/");
}

static void seed_policies(bool allow_shell)
{
    if (access(su_cfg.policies, F_OK) == 0) return;
    policy_set(SU_UID_SHELL, allow_shell ? SU_POLICY_ALLOW : SU_POLICY_ASK, 0);
    logmsg("seeded %s with uid %d = %s", su_cfg.policies, SU_UID_SHELL,
           allow_shell ? "allow" : "ask");
}

int main(int argc, char **argv)
{
    bool allow_shell = true;
    int lfd;
    int devnull;

    su_config_load();

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f")) foreground = true;
        else if (!strcmp(argv[i], "-n")) allow_shell = false;
        else {
            fprintf(stderr, "usage: sud [-f] [-n]\n");
            return 2;
        }
    }

    if (!foreground) {
        daemonize();
        logfd = open(su_cfg.log, O_WRONLY | O_CREAT | O_APPEND, 0644);
        devnull = open("/dev/null", O_RDWR);
        if (logfd >= 0) {
            dup2(logfd, 1);
            dup2(logfd, 2);
        }
        if (devnull >= 0) dup2(devnull, 0);
    } else {
        logfd = open(su_cfg.log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    if (logfd < 0) logfd = 2;

    signal(SIGCHLD, SIG_IGN);           /* connection handlers are reaped */
    signal(SIGHUP, SIG_IGN);            /* outlive the shell that started us */
    signal(SIGPIPE, SIG_IGN);

    if (geteuid() != 0) {
        logmsg("FATAL: euid=%d, must be root -- start sud from the rshell channel",
               (int)geteuid());
        return 1;
    }

    seed_policies(allow_shell);
    set_owner(su_cfg.log, 0, SU_UID_SHELL, 0660);
    lfd = listen_socket();
    if (lfd < 0) {
        logmsg("FATAL: cannot listen on %s: %s", su_cfg.sock, strerror(errno));
        return 1;
    }

    {
        FILE *f = fopen(su_cfg.pid, "we");
        if (f) {
            fprintf(f, "%d\n", (int)getpid());
            fclose(f);
            set_owner(su_cfg.pid, 0, SU_UID_SHELL, 0644);
        }
    }
    logmsg("sud %s up: uid=%d pid=%d socket=%s", SU_VERSION, (int)geteuid(),
           (int)getpid(), su_cfg.sock);

    for (;;) {
        struct ucred cred;
        socklen_t len = sizeof cred;
        int conn = accept(lfd, NULL, NULL);
        pid_t pid;

        if (conn < 0) {
            if (errno == EINTR) continue;
            logmsg("accept: %s", strerror(errno));
            break;
        }
        if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
            close(conn);
            continue;
        }
        pid = fork();
        if (pid == 0) {
            signal(SIGCHLD, SIG_DFL);
            close(lfd);
            handle(conn, cred.uid);
            close(conn);
            _exit(0);
        }
        close(conn);
    }
    unlink(su_cfg.sock);
    return 0;
}
