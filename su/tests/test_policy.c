/* tests/test_policy.c -- the policy parser and formatter.
 *
 * Links policy.c directly (no device, no I/O), so a round trip is checkable
 * here instead of on the tablet.
 */
#include <stdio.h>
#include <string.h>

#include "policy.h"

static int failures;

#define CHECK(cond, ...) do {                          \
    if (!(cond)) {                                     \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);    \
        printf(__VA_ARGS__);                           \
        putchar('\n');                                 \
        failures++;                                    \
    }                                                  \
} while (0)

static void test_names(void)
{
    CHECK(su_parse_policy("allow") == SU_POLICY_ALLOW, "allow");
    CHECK(su_parse_policy("deny") == SU_POLICY_DENY, "deny");
    CHECK(su_parse_policy("ask") == SU_POLICY_ASK, "ask");
    /* Magisk's numeric form is accepted too */
    CHECK(su_parse_policy("1") == SU_POLICY_ALLOW, "1");
    CHECK(su_parse_policy("0") == SU_POLICY_DENY, "0");
    CHECK(su_parse_policy("2") == SU_POLICY_ASK, "2");
    CHECK(su_parse_policy("nonsense") == -1, "nonsense");
    CHECK(su_parse_policy("") == -1, "empty");

    CHECK(!strcmp(su_policy_name(SU_POLICY_ALLOW), "allow"), "name allow");
    CHECK(!strcmp(su_policy_name(SU_POLICY_DENY), "deny"), "name deny");
    CHECK(!strcmp(su_policy_name(SU_POLICY_ASK), "ask"), "name ask");
}

static void test_line_parse(void)
{
    struct su_pol e;

    CHECK(su_parse_policy_line("2000 allow 0\n", &e) == 0, "basic");
    CHECK(e.uid == 2000 && e.policy == SU_POLICY_ALLOW && e.until == 0, "values");

    /* the expiry is optional */
    CHECK(su_parse_policy_line("10001 ask\n", &e) == 0, "no expiry");
    CHECK(e.uid == 10001 && e.policy == SU_POLICY_ASK && e.until == 0, "ask 0");

    CHECK(su_parse_policy_line("  10001   deny 1700000000\n", &e) == 0, "spaces");
    CHECK(e.until == 1700000000, "expiry");

    /* comments, blanks and junk are skipped by the caller, not parsed */
    CHECK(su_parse_policy_line("# a comment\n", &e) == -1, "comment");
    CHECK(su_parse_policy_line("\n", &e) == -1, "blank");
    CHECK(su_parse_policy_line("10001\n", &e) == -1, "missing policy");
    CHECK(su_parse_policy_line("10001 sometimes 0\n", &e) == -1, "bad policy");
    CHECK(su_parse_policy_line("", &e) == -1, "empty");
}

static void test_line_format(void)
{
    char buf[64];
    struct su_pol e;
    int n;

    n = su_format_policy_line(buf, sizeof buf, 2000, SU_POLICY_ALLOW, 0);
    CHECK(n == (int)strlen("2000 allow 0\n"), "format len");
    CHECK(!strcmp(buf, "2000 allow 0\n"), "format text: %s", buf);

    /* what we write is what we read back */
    CHECK(su_parse_policy_line(buf, &e) == 0, "round trip parse");
    CHECK(e.uid == 2000 && e.policy == SU_POLICY_ALLOW && e.until == 0, "round trip");

    n = su_format_policy_line(buf, sizeof buf, 10001, SU_POLICY_DENY, 1700000000);
    CHECK(n > 0 && !strcmp(buf, "10001 deny 1700000000\n"), "format deny: %s", buf);

    /* a too-small buffer is refused, not truncated */
    n = su_format_policy_line(buf, 4, 2000, SU_POLICY_ALLOW, 0);
    CHECK(n == -1, "small cap");
}

int main(void)
{
    test_names();
    test_line_parse();
    test_line_format();
    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("policy: all checks passed\n");
    return 0;
}
