/* policy.c -- see policy.h */
#include <stdio.h>
#include <string.h>

#include "policy.h"

int su_parse_policy(const char *s)
{
    if (!strcmp(s, "allow") || !strcmp(s, "1")) return SU_POLICY_ALLOW;
    if (!strcmp(s, "deny")  || !strcmp(s, "0")) return SU_POLICY_DENY;
    if (!strcmp(s, "ask")   || !strcmp(s, "2")) return SU_POLICY_ASK;
    return -1;
}

const char *su_policy_name(int policy)
{
    switch (policy) {
    case SU_POLICY_ALLOW: return "allow";
    case SU_POLICY_DENY:  return "deny";
    case SU_POLICY_ASK:   return "ask";
    }
    return "?";
}

int su_parse_policy_line(const char *line, struct su_pol *out)
{
    char name[16];
    long long uid, until = 0;
    int policy;

    while (*line == ' ' || *line == '\t') line++;
    if (*line == '#' || *line == '\n' || !*line) return -1;
    /* until is optional: "uid ask" is a complete line */
    if (sscanf(line, "%lld %15s %lld", &uid, name, &until) < 2) return -1;
    policy = su_parse_policy(name);
    if (policy < 0) return -1;
    if (uid < 0) return -1;

    out->uid = (uid_t)uid;
    out->policy = policy;
    out->until = until;
    return 0;
}

int su_format_policy_line(char *buf, size_t cap, uid_t uid, int policy,
                          int64_t until)
{
    int n = snprintf(buf, cap, "%u %s %lld\n", (unsigned)uid,
                     su_policy_name(policy), (long long)until);

    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}
