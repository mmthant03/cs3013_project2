#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
// These values MUST match the unistd_32.h modifications:
#define __NR_new_sys_cs3013_syscall1 377

long testCall1 ( void) {
    return (long) syscall(__NR_new_sys_cs3013_syscall1);
}

int main () {
printf("The return values of the system calls are:\n");
printf("\tcs3013_syscall1: %ld\n", testCall1());

FILE* testFile = fopen("testFile.txt", "r");
return 0;
}