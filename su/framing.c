/* framing.c -- see framing.h */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "framing.h"

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

int su_send_request(int fd, const struct su_req *req, const char *payload,
                    const int *fds)
{
    struct iovec iov[2];
    struct msghdr msg;
    char cmsgbuf[CMSG_SPACE(3 * sizeof(int))];
    int niov = 1;

    memset(&msg, 0, sizeof msg);
    iov[0].iov_base = (void *)req;
    iov[0].iov_len = sizeof *req;
    if (payload && req->len) {
        iov[1].iov_base = (void *)payload;
        iov[1].iov_len = req->len;
        niov = 2;
    }
    msg.msg_iov = iov;
    msg.msg_iovlen = niov;
    if (fds) {
        struct cmsghdr *c;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof cmsgbuf;
        c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(3 * sizeof(int));
        memcpy(CMSG_DATA(c), fds, 3 * sizeof(int));
    }
    return sendmsg(fd, &msg, 0) < 0 ? -1 : 0;
}

int su_recv_request(int fd, struct su_req *req, char **payload, int fds[3])
{
    struct iovec iov = { req, sizeof *req };
    char cmsgbuf[CMSG_SPACE(3 * sizeof(int))];
    struct msghdr msg;
    char *buf = NULL;

    *payload = NULL;
    if (fds) fds[0] = fds[1] = fds[2] = -1;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof cmsgbuf;

    if (recvmsg(fd, &msg, 0) != (ssize_t)sizeof *req) return -1;
    if (req->magic != SU_MAGIC) return -1;
    /* a peer on the world-connectable socket must not be able to ask for an
     * unbounded allocation */
    if (req->len > SU_MAX_PAYLOAD) return -1;

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (fds && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            int n = (int)((c->cmsg_len - CMSG_LEN(0)) / sizeof(int));
            for (int i = 0; i < n && i < 3; i++)
                memcpy(&fds[i], CMSG_DATA(c) + i * sizeof(int), sizeof(int));
        }
    }

    if (req->len) {
        /* +4 slack: callers NUL-split the payload and may read one byte past
         * its last string, so the buffer must have room for a terminator */
        buf = calloc(1, req->len + 4);
        if (!buf) return -1;
        if (read_all(fd, buf, req->len) != 0) {
            free(buf);
            return -1;
        }
    }
    *payload = buf;
    return 0;
}

int su_send_reply(int fd, int32_t rc, const char *text)
{
    struct su_reply r;

    r.rc = rc;
    r.len = text ? (uint32_t)strlen(text) : 0;
    if (write_all(fd, &r, sizeof r) != 0) return -1;
    if (r.len && write_all(fd, text, r.len) != 0) return -1;
    return 0;
}

int su_recv_reply(int fd, struct su_reply *rep, char **text)
{
    *text = NULL;
    if (read_all(fd, rep, sizeof *rep) != 0) return -1;
    if (rep->len > SU_MAX_PAYLOAD) return -1;
    if (rep->len) {
        char *t = malloc(rep->len + 1);
        if (!t) return -1;
        if (read_all(fd, t, rep->len) != 0) {
            free(t);
            return -1;
        }
        t[rep->len] = 0;
        *text = t;
    }
    return 0;
}
