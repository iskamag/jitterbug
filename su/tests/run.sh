#!/bin/sh
# run.sh -- build and run the host tests for the su subsystem.
#
# These link policy.c and framing.c (the parts with no device dependency)
# against the host libc, so the parser and the wire contract are checkable
# without a tablet.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SU="$(dirname "$DIR")"
CC="${CC:-cc}"
CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter -I$SU"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

rc=0
for t in test_policy test_framing; do
    "$CC" $CFLAGS -o "$TMP/$t" "$DIR/$t.c" "$SU/policy.c" "$SU/framing.c"
    if "$TMP/$t"; then :; else rc=1; fi
    echo
done
exit $rc
