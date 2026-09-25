/* client.c -- client side of the sud protocol (su and sumgr share it) */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "client.h"

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

int su_connect(const char *path)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) return -1;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int su_call(int fd, struct su_req *req, const char *payload, const int *fds,
            struct su_reply *rep, char **text)
{
    struct iovec iov[2];
    struct msghdr msg;
    char cmsgbuf[CMSG_SPACE(3 * sizeof(int))];
    int niov = 1;

    memset(&msg, 0, sizeof msg);
    iov[0].iov_base = req;
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
    if (sendmsg(fd, &msg, 0) < 0)
        return -1;

    if (read_all(fd, rep, sizeof *rep) != 0)
        return -1;
    *text = NULL;
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
    return rep->rc;
}

