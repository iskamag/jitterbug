/* client.h -- client side of the sud protocol (su and sumgr share it) */
#ifndef SU_CLIENT_H
#define SU_CLIENT_H

#include "proto.h"

/* returns a connected socket, or -1 (errno set) */
int su_connect(const char *path);

/* one request, one reply.  fds are passed as SCM_RIGHTS when non-NULL (RUN).
 * On success *text is a malloc'd reply string (or NULL) that the caller
 * frees; returns the reply's rc, or -1 on a transport error. */
int su_call(int fd, struct su_req *req, const char *payload, const int *fds,
            struct su_reply *rep, char **text);


#endif
