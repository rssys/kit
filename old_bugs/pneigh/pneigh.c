#define _GNU_SOURCE
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)
int open_netlink()
{
    struct sockaddr_nl saddr;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));

    return sock;
}

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* Add new data to rtattr */
int rtattr_add(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        fprintf(stderr, "rtattr_add error: message exceeded bound of %d\n", maxlen);
        return -1;
    }

    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len; 

    if (alen) {
        memcpy(RTA_DATA(rta), data, alen);
    }

    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return 0;
}

void add_pneigh(int s, const char * ifn, const char *ip) {
    struct {
        struct nlmsghdr n;
        struct ndmsg r;
        char buf[4096];
    } nl_request;

    nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    nl_request.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nl_request.n.nlmsg_type = RTM_NEWNEIGH;
    nl_request.r.ndm_family = AF_INET;
    nl_request.r.ndm_ifindex = if_nametoindex(ifn);
    nl_request.r.ndm_flags = NTF_PROXY;
    nl_request.r.ndm_state = NUD_PERMANENT;

    unsigned int ip_addr;
    inet_pton(AF_INET, ip, &ip_addr);
    rtattr_add(&nl_request.n, sizeof(nl_request), NDA_DST, &ip_addr, 4);
    if(send(s, &nl_request, nl_request.n.nlmsg_len, 0) < 0) {
        errExit("send");
    }
}

void bring_up(const char *ifn) {

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        errExit("socket");
    }
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifn, IFNAMSIZ);
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        char errmsg[30] = {0};
        snprintf(errmsg, sizeof(errmsg), "bring up %s", ifn);
        errExit(errmsg);
    }
    close(s);
}

int main() {
    int s;
    char x;
    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        errExit("pipe");
    }
    close(s);
    int pid = fork();
    if (pid < 0) {
        errExit("fork");
    }
    if (pid == 0) {
        // init net ns watchdog
        close(pipe_fd[1]);
        if (read(pipe_fd[0], &x, 1) < 0) {
            errExit("read");
        }
        if ((s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
            errExit("rtnetlink socket");
        }
        add_pneigh(s, "lo", "127.0.0.2");
        system("cat /proc/net/arp");
        return 0;
    }
    close(pipe_fd[0]);
    unshare(CLONE_NEWNET);
    bring_up("lo");
    if ((s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        errExit("rtnetlink socket");
    }
    add_pneigh(s, "lo", "127.0.0.2");
    if (write(pipe_fd[1], &x, 1) < 0) {
        errExit("write");
    }
    wait(NULL);
    return 0;
}