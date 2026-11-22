#pragma once

typedef long pd_ssize_t;

long pd_sys_open(const char *, int, int);
long pd_sys_close(int);
pd_ssize_t pd_sys_read(int, void *, unsigned long);
pd_ssize_t pd_sys_write(int, const void *, unsigned long);
long pd_sys_execve(const char *, char *const [], char *const []);
long pd_sys_reboot(int, const char *);

__attribute__((noreturn))
static inline void pd_exit_forever(void)
{
    for (;;) __asm__ volatile("pause");
}
