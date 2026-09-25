/* config.h -- where the pieces live, and who may manage policies.
 *
 * Every value has a compiled default and an environment override, so the
 * same binaries work on any Android where sud runs as root:
 *
 *   SU_DIR          toolbox dir        (default /data/local/tmp)
 *   SU_MANAGER_PKG  manager app pkg    (default com.matepad.sumgr)
 *   SU_SHELL_PKG    second trusted pkg (default com.termux)
 *
 * The socket must be reachable by app uids; the policy file must not be
 * writable by them (0660 root:shell), which is what SU_UID_SHELL is for.
 */
#ifndef SU_CONFIG_H
#define SU_CONFIG_H

#include <sys/types.h>

/* the shell uid: adb and a Termux shell both run as this */
#define SU_UID_SHELL 2000

struct su_config {
    char sock[256];
    char policies[256];
    char pending[256];
    char log[256];
    char pid[256];
    char manager_pkg[128];
    char shell_pkg[128];
    char request_act[256];      /* manager_pkg + "/.RequestActivity" */
};

extern struct su_config su_cfg;

/* fill su_cfg from the environment + defaults; call once at startup */
void su_config_load(void);

#endif
