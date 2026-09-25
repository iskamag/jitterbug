/* proto.h -- wire format between su / sumgr (clients) and sud (daemon).
 *
 * One request, one reply.  For a root shell the client's three stdio fds
 * travel out of band as SCM_RIGHTS, so the shell the daemon forks inherits
 * the caller's tty verbatim (job control included).
 */
#ifndef SU_PROTO_H
#define SU_PROTO_H

#include <stdint.h>

#define SU_MAGIC    0x53554431u         /* "SUD1" */
#define SU_VERSION  "1.0"

/* paths -- /data/local/tmp because that is where this operation keeps its
 * per-boot toolbox; the socket must be reachable by app uids, the policy
 * file must not be writable by them (only rwx for owner/group: root/shell) */
#define SU_SOCKET    "/data/local/tmp/su.sock"
#define SU_POLICIES  "/data/local/tmp/su.policies"
#define SU_PENDING   "/data/local/tmp/su.pending"
#define SU_LOG       "/data/local/tmp/sud.log"
#define SU_PID       "/data/local/tmp/sud.pid"

/* the manager app: uid is resolved from /data/system/packages.list, and
 * RequestActivity is what the daemon launches to prompt for a new requester */
#define SU_MANAGER_PKG  "com.matepad.sumgr"
#define SU_REQUEST_ACT  SU_MANAGER_PKG "/.RequestActivity"

/* the other package whose uid may manage policies: this operation is driven
 * from a Termux shell, and its uid is no more privileged than the app whose
 * dialogs it will be answering */
#define SU_SHELL_PKG    "com.termux"

enum su_op {
    SU_OP_RUN     = 1,  /* fork a root shell (su) */
    SU_OP_LIST    = 2,  /* policy table (manager) */
    SU_OP_SET     = 3,  /* set one policy (manager) */
    SU_OP_PENDING = 4,  /* outstanding requests (manager) */
    SU_OP_LOG     = 5,  /* recent decisions (manager) */
    SU_OP_STOP    = 6,  /* shut the daemon down (manager) */
};

/* Magisk's numbering, so the code reads like every other su out there */
enum su_policy {
    SU_POLICY_DENY  = 0,
    SU_POLICY_ALLOW = 1,
    SU_POLICY_ASK   = 2,
};

struct su_req {
    uint32_t magic;
    uint32_t op;                        /* enum su_op */
    uint32_t uid;                       /* SET: target uid; else 0 */
    uint32_t policy;                    /* SET: enum su_policy */
    int64_t  until;                     /* SET: unix seconds, 0 = permanent */
    uint32_t len;                       /* payload bytes */
    /* RUN payload: shell\0 cmd\0 env ... (cmd empty = interactive shell) */
};

struct su_reply {
    int32_t  rc;                        /* RUN: exit status; else 0 = ok */
    uint32_t len;                       /* text bytes following */
};

/* uids allowed to manage policies.  The shell uid (adb, Termux) is included
 * because it already reaches root through the rshell channel per boot, so
 * this grants it nothing new; app uids are only trusted when they own
 * SU_MANAGER_PKG. */
#define SU_UID_SHELL 2000

#endif
