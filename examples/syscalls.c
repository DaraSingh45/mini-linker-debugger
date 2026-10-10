#include "syscalls.h"

long sys_write(int fd, const void *buf, unsigned long len)
{
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(1), "D"(fd), "S"(buf), "d"(len)
                     : "rcx", "r11", "memory");
    return ret;
}

void write_str(const char *s)
{
    unsigned long n = 0;
    while (s[n])
        n++;
    sys_write(1, s, n);
}

void write_int(int value)
{
    char buf[16];
    int pos = sizeof(buf);
    unsigned int u = value < 0 ? -(unsigned int)value : (unsigned int)value;
    buf[--pos] = '\n';
    do {
        buf[--pos] = '0' + (u % 10);
        u /= 10;
    } while (u);
    if (value < 0)
        buf[--pos] = '-';
    sys_write(1, buf + pos, sizeof(buf) - pos);
}

void write_label_int(const char *label, int value)
{
    write_str(label);
    write_int(value);
}
