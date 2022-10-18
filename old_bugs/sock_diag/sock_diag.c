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
#include <fcntl.h>
#include <arpa/inet.h>


#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/unix_diag.h> 
#include <linux/sock_diag.h> 
#include <linux/rtnetlink.h> 
#include <sys/stat.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)
#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

// https://man7.org/linux/man-pages/man7/sock_diag.7.html
static int
print_diag(const struct unix_diag_msg *diag, unsigned int len)
{
    if (len < NLMSG_LENGTH(sizeof(*diag))) {
        fputs("short response\n", stderr);
        return -1;
    }
    if (diag->udiag_family != AF_UNIX) {
        fprintf(stderr, "unexpected family %u\n", diag->udiag_family);
        return -1;
    }

    unsigned int rta_len = len - NLMSG_LENGTH(sizeof(*diag));
    unsigned int peer = 0;
    size_t path_len = 0;
    char path[sizeof(((struct sockaddr_un *) 0)->sun_path) + 1];

    for (struct rtattr *attr = (struct rtattr *) (diag + 1);
            RTA_OK(attr, rta_len); attr = RTA_NEXT(attr, rta_len)) {
        switch (attr->rta_type) {
        case UNIX_DIAG_NAME:
            if (!path_len) {
                path_len = RTA_PAYLOAD(attr);
                if (path_len > sizeof(path) - 1)
                    path_len = sizeof(path) - 1;
                memcpy(path, RTA_DATA(attr), path_len);
                path[path_len] = '\0';
            }
            break;

        case UNIX_DIAG_PEER:
            if (RTA_PAYLOAD(attr) >= sizeof(peer))
                peer = *(unsigned int *) RTA_DATA(attr);
            break;
        }
    }

    printf("inode=%u", diag->udiag_ino);

    if (peer)
        printf(", peer=%u", peer);

    if (path_len)
        printf(", name=%s%s", *path ? "" : "@",
                *path ? path : path + 1);

    putchar('\n');
    return 0;
}

int main() {
    char x;
    int pipe_fd[2], pipe_fd1[2];
    if (pipe(pipe_fd) < 0) {
        errExit("pipe");
    }
    if (pipe(pipe_fd1) < 0) {
        errExit("pipe1");
    }
    
    int s;
    if ((s=socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        errExit("socket");
    }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "./un");
    if (bind(s, &addr, sizeof(addr)) < 0) {
        errExit("bind");
    }
    struct stat file_stat;  
    if (fstat(s, &file_stat) < 0) {
        errExit("fstat");
    }
    int ino = file_stat.st_ino;
    int pid = fork();
    if (pid < 0) {
        errExit("fork");
    }
    if (pid == 0) {
        unshare(CLONE_NEWNET);
        close(pipe_fd[1]);
        close(pipe_fd1[0]);
        int s;
        if ((s = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)) < 0) {
            errExit("sock");
        }
        struct {
            struct nlmsghdr n;
            struct unix_diag_req r;
        } nl_request = {
            .n = {
                .nlmsg_len=sizeof(nl_request),
                .nlmsg_type=SOCK_DIAG_BY_FAMILY,
                .nlmsg_flags=NLM_F_REQUEST 
            },
            .r = {
                .sdiag_family=AF_UNIX,
                .sdiag_protocol=0,
                .udiag_states=-1,
                .udiag_ino=ino,
                .udiag_show=UDIAG_SHOW_NAME,
                .pad=0,
                .udiag_cookie = {~0U, ~0U}
            }
        };
        if (send(s, &nl_request, nl_request.n.nlmsg_len, 0) < 0) {
            errExit("send");
        }

        char buf[1024] = {0};
        int ret = recv(s, buf, sizeof(buf), 0);

        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        if (!NLMSG_OK(h, ret)) {
            errExit("response not ok");
        }
        for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                return 0;
            }

            if (h->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *err = NLMSG_DATA(h);

                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
                    fputs("NLMSG_ERROR\n", stderr);
                } else {
                    errno = -err->error;
                    perror("NLMSG_ERROR");
                }

                return -1;
            }

            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                fprintf(stderr, "unexpected nlmsg_type %u\n",
                        (unsigned) h->nlmsg_type);
                return -1;
            }

            if (print_diag(NLMSG_DATA(h), h->nlmsg_len))
                return -1;
        }
        
        return 0;
    }
    close(pipe_fd[0]);
    close(pipe_fd1[1]);
    wait(NULL);
    return 0;
}