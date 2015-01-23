#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#define PAGE_SIZE 4096
#define PROC_CFG_INFO "/proc/cfginfo"

int main(int argc, char* argv[])
{
	if(argc != 2) {
		printf("Usage: %s string\n", argv[0]);
		return 0;
	}
	char s[256];
	int fd;
	if( (fd = open(PROC_CFG_INFO, O_RDONLY)) < 0) {
		printf("cannot open file /proc/shm_dir/shm_info, error:[%d]\n", errno);
		return 0;
	}
	read(fd, s, 256);
	printf("%lx\n", *(unsigned long*)s);

	close(fd);
	return 0;
}
