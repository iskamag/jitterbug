/* tests/test_framing.c -- the wire framing, over a socketpair.
 *
 * What this pins down is the boundary the daemon has to defend: a peer on a
 * world-connectable socket must not be able to make it allocate more than
 * SU_MAX_PAYLOAD, and a truncated payload must be refused rather than read
 * past its buffer.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "framing.h"
#include "proto.h"

static int failures;

#define CHECK(cond, ...) do {                          \
    if (!(cond)) {                                     \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);    \
        printf(__VA_ARGS__);                           \
        putchar('\n');                                 \
        failures++;                                    \
    }                                                  \
} while (0)

static struct su_req base_req(uint32_t op, uint32_t len)
{
    struct su_req r;

    memset(&r, 0, sizeof r);
    r.magic = SU_MAGIC;
    r.op = op;
    r.len = len;
    return r;
}

/* full round trip: request, payload and SCM_RIGHTS fds all survive */
static void test_round_trip(int *fds)
{
    int sv[2], in_fds[3] = { -1, -1, -1 };
    struct su_req out = base_req(SU_OP_RUN, 0), in;
    struct su_reply rep, got;
    char *payload = NULL, *text = NULL;

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(su_send_request(sv[0], &out, NULL, fds) == 0, "send");
    CHECK(su_recv_request(sv[1], &in, &payload, in_fds) == 0, "recv");
    CHECK(in.magic == SU_MAGIC && in.op == SU_OP_RUN, "header");
    CHECK(payload == NULL, "no payload");
    free(payload);

    rep.rc = 7;
    rep.len = 5;
    CHECK(su_send_reply(sv[1], rep.rc, "hello") == 0, "send reply");
    CHECK(su_recv_reply(sv[0], &got, &text) == 0, "recv reply");
    CHECK(got.rc == 7, "rc %d", got.rc);
    CHECK(text && !strcmp(text, "hello"), "text");
    free(text);
    close(sv[0]);
    close(sv[1]);
}

/* the fds really do arrive, and stay -1 when the sender attaches none */
static void test_fds(void)
{
    int sv[2], in_fds[3] = { -1, -1, -1 }, send_fds[3] = { 0, 1, 2 };
    struct su_req out = base_req(SU_OP_RUN, 0), in;
    char *payload = NULL;

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(su_send_request(sv[0], &out, NULL, send_fds) == 0, "send fds");
    CHECK(su_recv_request(sv[1], &in, &payload, in_fds) == 0, "recv fds");
    CHECK(in_fds[0] >= 0 && in_fds[1] >= 0 && in_fds[2] >= 0, "fds arrived");
    for (int i = 0; i < 3; i++)
        if (in_fds[i] > 2) close(in_fds[i]);

    CHECK(su_send_request(sv[0], &out, NULL, NULL) == 0, "send none");
    CHECK(su_recv_request(sv[1], &in, &payload, in_fds) == 0, "recv none");
    CHECK(in_fds[0] == -1 && in_fds[1] == -1 && in_fds[2] == -1, "no fds");
    free(payload);
    close(sv[0]);
    close(sv[1]);
}

/* payload bytes arrive intact */
static void test_payload(void)
{
    int sv[2];
    struct su_req out, in;
    char *payload = NULL;
    const char body[] = "/system/bin/sh\0id\0";

    out = base_req(SU_OP_RUN, sizeof body);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(su_send_request(sv[0], &out, body, NULL) == 0, "send payload");
    CHECK(su_recv_request(sv[1], &in, &payload, NULL) == 0, "recv payload");
    CHECK(in.len == sizeof body, "len");
    CHECK(payload && !memcmp(payload, body, sizeof body), "body");
    free(payload);
    close(sv[0]);
    close(sv[1]);
}

/* a header asking for more than SU_MAX_PAYLOAD is refused before any alloc */
static void test_oversized(void)
{
    int sv[2];
    struct su_req out = base_req(SU_OP_RUN, SU_MAX_PAYLOAD + 1), in;
    char *payload = NULL;

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(su_send_request(sv[0], &out, NULL, NULL) == 0, "send");
    CHECK(su_recv_request(sv[1], &in, &payload, NULL) == -1, "refused");
    CHECK(payload == NULL, "nothing allocated");
    close(sv[0]);
    close(sv[1]);
}

/* a wrong magic is refused */
static void test_bad_magic(void)
{
    int sv[2];
    struct su_req out = base_req(SU_OP_RUN, 0), in;
    char *payload = NULL;

    out.magic = 0xdeadbeef;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(su_send_request(sv[0], &out, NULL, NULL) == 0, "send");
    CHECK(su_recv_request(sv[1], &in, &payload, NULL) == -1, "refused");
    close(sv[0]);
    close(sv[1]);
}

/* a payload that never arrives (sender closes) is refused, no leak */
static void test_truncated(void)
{
    int sv[2];
    struct su_req out = base_req(SU_OP_RUN, 16), in;
    char *payload = NULL;

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(su_send_request(sv[0], &out, NULL, NULL) == 0, "send header only");
    close(sv[0]);                                  /* the body never comes */
    CHECK(su_recv_request(sv[1], &in, &payload, NULL) == -1, "refused");
    CHECK(payload == NULL, "nothing left to free");
    close(sv[1]);
}

int main(void)
{
    int fds[3] = { 0, 1, 2 };

    test_round_trip(fds);
    test_fds();
    test_payload();
    test_oversized();
    test_bad_magic();
    test_truncated();
    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("framing: all checks passed\n");
    return 0;
}
