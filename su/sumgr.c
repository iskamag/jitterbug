/* sumgr.c -- the manager CLI: list, grant, revoke, watch.
 *
 * The GUI manager app speaks the same socket, but a root shell always needs a
 * way to fix things when the app is not around (or when it is the app that
 * needs the grant).
 *
 *   sumgr list                 uid, policy, expiry, package
 *   sumgr pending              requests waiting for an answer
 *   sumgr log                  recent decisions
 *   sumgr allow <uid> [mins]   grant (mins omitted = permanent)
 *   sumgr deny  <uid>          revoke
 *   sumgr ask   <uid>          prompt every time
 *   sumgr stop                 shut the daemon down
 *
 * It runs as whoever invokes it; the daemon trusts root, the shell uid, and
 * the manager app's uid (see proto.h).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "client.h"
#include "proto.h"

static void usage(void)
{
    fputs("usage: sumgr list|pending|log|stop\n"
          "       sumgr allow <uid> [minutes] | deny <uid> | ask <uid>\n", stderr);
}

static int call(struct su_req *req)
{
    struct su_reply rep;
    char *text = NULL;
    int fd = su_connect(SU_SOCKET);
    int rc;

    if (fd < 0) {
        fprintf(stderr, "sumgr: cannot reach %s: %s\n"
                        "       is sud running? (tools/su/install.sh)\n",
                SU_SOCKET, strerror(errno));
        return 1;
    }
    rc = su_call(fd, req, NULL, NULL, &rep, &text);
    close(fd);
    if (rc < 0) {
        fprintf(stderr, "sumgr: no reply from sud\n");
        return 1;
    }
    if (text) {
        fputs(text, stdout);
        free(text);
    }
    return rep.rc;
}

static int parse_uid(const char *s, uint32_t *uid)
{
    char *end;
    long v = strtol(s, &end, 10);

    if (*s == 0 || *end != 0 || v < 0 || v > 0x7fffffff) return -1;
    *uid = (uint32_t)v;
    return 0;
}

int main(int argc, char **argv)
{
    struct su_req req;

    memset(&req, 0, sizeof req);
    req.magic = SU_MAGIC;

    if (argc < 2) {
        usage();
        return 2;
    }
    if (!strcmp(argv[1], "list")) {
        req.op = SU_OP_LIST;
        return call(&req);
    }
    if (!strcmp(argv[1], "pending")) {
        req.op = SU_OP_PENDING;
        return call(&req);
    }
    if (!strcmp(argv[1], "log")) {
        req.op = SU_OP_LOG;
        return call(&req);
    }
    if (!strcmp(argv[1], "stop")) {
        req.op = SU_OP_STOP;
        return call(&req);
    }
    if (!strcmp(argv[1], "allow") || !strcmp(argv[1], "deny") ||
        !strcmp(argv[1], "ask")) {
        uint32_t uid;
        if (argc < 3 || parse_uid(argv[2], &uid) != 0) {
            usage();
            return 2;
        }
        req.op = SU_OP_SET;
        req.uid = uid;
        req.policy = !strcmp(argv[1], "allow") ? SU_POLICY_ALLOW :
                     !strcmp(argv[1], "deny")  ? SU_POLICY_DENY :
                                                 SU_POLICY_ASK;
        if (argc > 3 && !strcmp(argv[1], "allow")) {
            char *end;
            long mins = strtol(argv[3], &end, 10);
            if (*end != 0 || mins < 0) {
                usage();
                return 2;
            }
            if (mins > 0) req.until = (int64_t)time(NULL) + mins * 60;
        }
        return call(&req);
    }
    usage();
    return 2;
}
