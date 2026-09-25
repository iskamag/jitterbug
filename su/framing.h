/* framing.h -- the sud wire protocol, one request one reply.
 *
 * Both ends use these so a malformed or oversized frame is rejected the same
 * way on each side.  A root shell request carries the client's three stdio
 * fds as SCM_RIGHTS, so the shell sud forks inherits the caller's tty
 * verbatim (job control included).
 */
#ifndef SU_FRAMING_H
#define SU_FRAMING_H

#include <stdint.h>

#include "proto.h"

/* Send struct su_req, then `payload` (req->len bytes) if non-NULL, with
 * `fds` (three ints) attached as SCM_RIGHTS if non-NULL.  0 on success. */
int su_send_request(int fd, const struct su_req *req, const char *payload,
                    const int *fds);

/* Receive one su_req plus its payload.  *payload is malloc'd (or NULL when
 * req->len is 0) and must be freed; fds[3] are set to -1 unless the sender
 * attached stdio fds.  Returns 0, or -1 on a truncated/short/oversized frame
 * (in which case nothing needs freeing). */
int su_recv_request(int fd, struct su_req *req, char **payload, int fds[3]);

/* Send one su_reply plus optional text.  0 on success. */
int su_send_reply(int fd, int32_t rc, const char *text);

/* Receive one su_reply plus optional text (*text is malloc'd, free it).
 * Returns 0 on success, -1 on a truncated frame. */
int su_recv_reply(int fd, struct su_reply *rep, char **text);

#endif
