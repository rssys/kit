#define _GNU_SOURCE
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)

int main() {
    char x;
    int pipe_fd[2], pipe_fd1[2];
    if (pipe(pipe_fd) < 0) {
        errExit("pipe");
    }
    if (pipe(pipe_fd1) < 0) {
        errExit("pipe1");
    }
    
    int pid = fork();
    if (pid < 0) {
        errExit("fork");
    }
    if (pid == 0) {
        close(pipe_fd[1]);
        close(pipe_fd1[0]);
        if (read(pipe_fd[0], &x, 1) < 0) {
            errExit("read");
        }
        printf("p = %d\n", getpriority(PRIO_USER, 0));
        return 0;
    }
    close(pipe_fd[0]);
    close(pipe_fd1[1]);
    unshare(CLONE_NEWPID);
    setpriority(PRIO_USER, 0, -11);
    if (write(pipe_fd[1], &x, 1) < 0) {
        errExit("write");
    }
    wait(NULL);
    return 0;
}