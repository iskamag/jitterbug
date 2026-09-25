/* client.h -- the client side of the sud protocol, shared by su and sumgr */
#ifndef SU_CLIENT_H
#define SU_CLIENT_H

#include "proto.h"

/* connect to the daemon's socket; -1 if it is not there */
int su_connect(void);

/* one request/reply round trip; `payload` may be NULL, `fds` may be NULL.
 * *text receives the reply's text (free it).  Returns rep.rc, or -1 if the
 * daemon closed the connection. */
int su_call(int fd, struct su_req *req, const char *payload, const int *fds,
            struct su_reply *rep, char **text);

#endif
