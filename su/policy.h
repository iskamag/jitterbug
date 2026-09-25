/* policy.h -- uid -> allow/deny/ask, the pure half of the policy table.
 *
 * No I/O here: parsing and formatting only, so the host tests link it
 * directly and sud.c keeps just the file plumbing.  Magisk's numbering, so
 * the values read like every other su out there.
 */
#ifndef SU_POLICY_H
#define SU_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum su_policy {
    SU_POLICY_DENY  = 0,
    SU_POLICY_ALLOW = 1,
    SU_POLICY_ASK   = 2,
};

/* a policy entry as read from SU_POLICIES */
struct su_pol {
    uid_t   uid;
    int     policy;
    int64_t until;          /* unix seconds; 0 = permanent */
};

/* "allow" / "deny" / "ask" (or the numeric equivalents); -1 if unknown */
int su_parse_policy(const char *s);

const char *su_policy_name(int policy);

/* one "uid policy until" line.  Blank lines and '#' comments yield -1, as
 * does anything malformed -- the caller just skips those. */
int su_parse_policy_line(const char *line, struct su_pol *out);

/* "uid policy until\n"; the number of bytes written, or -1 if cap is too
 * small (nothing is written in that case). */
int su_format_policy_line(char *buf, size_t cap, uid_t uid, int policy,
                          int64_t until);

#endif
