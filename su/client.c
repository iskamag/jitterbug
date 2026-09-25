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
#include "config.h"
#include "framing.h"

int su_connect(void)
{
    struct sockaddr_un addr;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd < 0) return -1;
    /* sun_path is 108 bytes; a longer SU_DIR would be silently truncated, so
     * refuse it instead of connecting to a mangled path */
    if (strlen(su_cfg.sock) >= sizeof addr.sun_path) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, su_cfg.sock, strlen(su_cfg.sock));
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int su_call(int fd, struct su_req *req, const char *payload, const int *fds,
            struct su_reply *rep, char **text)
{
    if (su_send_request(fd, req, payload, fds) != 0) return -1;
    if (su_recv_reply(fd, rep, text) != 0) return -1;
    return rep->rc;
}
