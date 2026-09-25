/* proto.h -- wire format between su / sumgr (clients) and sud (daemon).
 *
 * One request, one reply.  For a root shell the client's three stdio fds
 * travel out of band as SCM_RIGHTS, so the shell the daemon forks inherits
 * the caller's tty verbatim (job control included).
 *
 * Only the wire types live here.  Where the socket and files live is
 * runtime configuration -- see config.h.  Which uids may manage policies is
 * derived from that too (the manager app's package), so nothing that differs
 * between installs is compiled in.
 */
#ifndef SU_PROTO_H
#define SU_PROTO_H

#include <stdint.h>

#define SU_MAGIC    0x53554431u         /* "SUD1" */
#define SU_VERSION  "1.0"

/* upper bound on any request/reply payload.  The socket is world-connectable,
 * so this is what stops a peer asking for an unbounded allocation. */
#define SU_MAX_PAYLOAD (1024u * 1024u)

enum su_op {
    SU_OP_RUN     = 1,  /* fork a root shell (su) */
    SU_OP_LIST    = 2,  /* policy table (manager) */
    SU_OP_SET     = 3,  /* set one policy (manager) */
    SU_OP_PENDING = 4,  /* outstanding requests (manager) */
    SU_OP_LOG     = 5,  /* recent decisions (manager) */
    SU_OP_STOP    = 6,  /* shut the daemon down (manager) */
};

struct su_req {
    uint32_t magic;
    uint32_t op;                        /* enum su_op */
    uint32_t uid;                       /* SET: target uid; else 0 */
    uint32_t policy;                    /* SET: enum su_policy (policy.h) */
    int64_t  until;                     /* SET: unix seconds, 0 = permanent */
    uint32_t len;                       /* payload bytes */
    /* RUN payload: shell\0 cmd\0 env ... (cmd empty = interactive shell) */
};

struct su_reply {
    int32_t  rc;                        /* RUN: exit status; else 0 = ok */
    uint32_t len;                       /* text bytes following */
};

#endif
