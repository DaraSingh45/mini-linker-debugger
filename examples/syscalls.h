#ifndef SYSCALLS_H
#define SYSCALLS_H
long sys_write(int fd, const void *buf, unsigned long len);
void write_str(const char *s);
void write_int(int value);
void write_label_int(const char *label, int value);
#endif
