#define _GNU_SOURCE
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
        unshare(CLONE_NEWNET);
        if (read(pipe_fd[0], &x, 1) < 0) {
            errExit("read");
        }
        system("cat /proc/net/nf_conntrack");
        return 0;
    }
    close(pipe_fd[0]);
    close(pipe_fd1[1]);
    int s;
    if ((s=socket(AF_INET, SOCK_STREAM, 0))< 0) {
        errExit("socket");
    }
    struct sockaddr_in addr_bind = {
        .sin_family=AF_INET,
        .sin_addr=inet_addr("127.0.0.1"),
        .sin_port=htons(12341)
    };
    struct sockaddr_in addr_to = {0}; 
    addr_to.sin_family = AF_INET;
    addr_to.sin_port = htons(3000);
    addr_to.sin_addr.s_addr = inet_addr("127.0.0.1");
    int pid1 = fork();
    if (pid1 < 0) {
        errExit("fork");
    }
    if (pid1 == 0) {
        if ((s=socket(AF_INET, SOCK_STREAM, 0))< 0) {
            errExit("socket");
        }
        if (bind(s, &addr_to, sizeof(addr_to)) < 0) {
            errExit("bind");
        }
        listen(s, 10);
        struct sockaddr_in addr_in = {0};
        int len;
        accept(s, &addr_in, &len);
        return 0;
    }
    // if (bind(s, &addr_bind, sizeof(addr_bind)) < 0) {
    //     errExit("bind shit");
    // }
    sleep(1);
    if (connect(s, &addr_to, sizeof(struct sockaddr_in)) < 0) {
        errExit("connect");
    }
    if (write(pipe_fd[1], &x, 1) < 0) {
        errExit("write");
    }
    wait(NULL);
    return 0;
}