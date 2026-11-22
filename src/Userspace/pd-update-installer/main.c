#include "runtime.h"

static const char manifest_path[] =
    "/Library/UpdateCache/manifest";
static const char signature_path[] =
    "/Library/UpdateCache/manifest.sig";
static const char archive_path[] =
    "/Library/UpdateCache/update.tar.xz";

static void report(const char *message, unsigned long length)
{
    (void)pd_sys_write(2, message, length);
}

static int readable_file(const char *path)
{
    long fd = pd_sys_open(path, 0, 0);
    if (fd < 0)
        return 0;

    char byte;
    pd_ssize_t result = pd_sys_read((int)fd, &byte, 1);
    (void)pd_sys_close((int)fd);

    return result >= 0;
}

__attribute__((noreturn))
void pd_update_installer_main(long *initial_stack)
{
    (void)initial_stack;

    /*
     * This is deliberately only the bootstrap stage.
     * No installed files are changed until manifest authentication,
     * archive verification, and transactional installation exist.
     */
    if (!readable_file(manifest_path)) {
        static const char message[] =
            "pd-update-installer: cannot read update manifest\n";
        report(message, sizeof(message) - 1);
        pd_update_stop();
    }

    if (!readable_file(signature_path)) {
        static const char message[] =
            "pd-update-installer: cannot read manifest signature\n";
        report(message, sizeof(message) - 1);
        pd_update_stop();
    }

    if (!readable_file(archive_path)) {
        static const char message[] =
            "pd-update-installer: cannot read update archive\n";
        report(message, sizeof(message) - 1);
        pd_update_stop();
    }

    static const char message[] =
        "pd-update-installer: verification and installation are not yet enabled\n";
    report(message, sizeof(message) - 1);
    pd_update_stop();
}
