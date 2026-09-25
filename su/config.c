/* config.c -- see config.h */
#include <stdio.h>
#include <stdlib.h>

#include "config.h"

struct su_config su_cfg;

static const char *env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

void su_config_load(void)
{
    const char *dir     = env_or("SU_DIR", "/data/local/tmp");
    const char *manager = env_or("SU_MANAGER_PKG", "com.matepad.sumgr");
    const char *shell   = env_or("SU_SHELL_PKG", "com.termux");

    snprintf(su_cfg.sock,     sizeof su_cfg.sock,     "%s/su.sock", dir);
    snprintf(su_cfg.policies, sizeof su_cfg.policies, "%s/su.policies", dir);
    snprintf(su_cfg.pending,  sizeof su_cfg.pending,  "%s/su.pending", dir);
    snprintf(su_cfg.log,      sizeof su_cfg.log,      "%s/sud.log", dir);
    snprintf(su_cfg.pid,      sizeof su_cfg.pid,      "%s/sud.pid", dir);
    snprintf(su_cfg.manager_pkg, sizeof su_cfg.manager_pkg, "%s", manager);
    snprintf(su_cfg.shell_pkg,   sizeof su_cfg.shell_pkg,   "%s", shell);
    snprintf(su_cfg.request_act, sizeof su_cfg.request_act, "%s/.RequestActivity",
             manager);
}
