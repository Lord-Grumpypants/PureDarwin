#include "runtime.h"

static char *launchd_argv[] = {
    "/sbin/launchd",
    0
};

static char *remount_argv[] = {
    "/usr/libexec/pd-root-remount",
    "--update",
    0
};

static char *empty_env[] = {
    0
};

__attribute__((noreturn))
void pd_init_main(long *initial_stack)
{
    (void)initial_stack;

    /*
     * A pending marker means an update has already been downloaded,
     * authenticated, and staged by the running system.
     */
    long fd = pd_sys_open(
        "/Library/UpdateCache/pending",
        0, 0
    );

    if (fd >= 0) {
        pd_sys_close((int)fd);
        pd_sys_execve(
            remount_argv[0],
            remount_argv,
            empty_env
        );
    } else if (fd == -2) {
        /* ENOENT: no pending update. */
        pd_sys_execve(
            launchd_argv[0],
            launchd_argv,
            empty_env
        );
    } else {
        static const char error[] =
            "pd-init: cannot inspect update marker; refusing normal startup\n";
        pd_sys_write(2, error, sizeof(error) - 1);
        pd_exit_forever();
    }

    static const char error[] =
        "pd-init: exec failed; refusing normal startup\n";

    pd_sys_write(2, error, sizeof(error) - 1);
    pd_exit_forever();
}
