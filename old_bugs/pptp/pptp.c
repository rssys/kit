#define _GNU_SOURCE
#include <sched.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/if_pppox.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <string.h>
#include <wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)
#define NL_MAX_PAYLOAD 8192

int pipe_fd[2];
char x;
int main() {
    system("cat /proc/net/dev");
    if (pipe(pipe_fd) < 0) {
        errExit("pipe");
    }
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
        system("cat /proc/net/dev");
        return 0;
    }
    close(pipe_fd[0]);

    // container
    if (unshare(CLONE_NEWNET) < 0) {
        errExit("unshare");
    }

    // bring up lo device
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        errExit("socket");
    }
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        errExit("bring lo up");
    }
    close(s);


    int f = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_PPTP);
    if (f < 0) {
        errExit("socket");
    }
    struct sockaddr_pppox s_addr = {
        .sa_family=AF_PPPOX,
        .sa_protocol=PX_PROTO_PPTP,
        .sa_addr.pptp={
            .call_id=0,
            .sin_addr.s_addr=inet_addr("127.0.0.1")
        }
    };
    struct sockaddr_pppox d_addr = {
        .sa_family=AF_PPPOX,
        .sa_protocol=PX_PROTO_PPTP,
        .sa_addr.pptp={
            .call_id=0,
            .sin_addr.s_addr=inet_addr("127.0.0.1")
        }
    };
    int ret;
    printf("f = %d\n", f);
    ret = bind(f, (struct sockaddr *)&s_addr, sizeof(s_addr));
    if (ret < 0) {
        errExit("bind");
    }

    // * look up the route
    // * create a PPP channel and notifying PPP generic layer by calling `ppp_register_channel`
    // * set PPP channel's mtu, hdrlen, etc.
    // * set PPTP(PPPOX) sock's dst_addr
    ret = connect(f, (struct sockaddr *)&d_addr, sizeof(d_addr));
    if (ret < 0) {
        errExit("connect");
    }

    /* get PPP channel index */
    int channel_idx;
    if (ioctl(f, PPPIOCGCHAN, &channel_idx) < 0) {
        errExit("pppox ioctl channel index");
    }
    printf("channel = %d\n", channel_idx);

    // PPP doc: https://www.kernel.org/doc/Documentation/networking/ppp_generic.txt
    // section: Interface to pppd

    // create a PPP instance
    int ppp_dev_fd = open("/dev/ppp", O_RDWR);
    if (ppp_dev_fd < 0) {
        errExit("open /dev/ppp");
    }

    // attach to the PPP channel
    if (ioctl(ppp_dev_fd, PPPIOCATTCHAN, &channel_idx) < 0) {
        errExit("attach to channel");
    }

    // write data to PPP channel
    char *data = "abcd";
    ret = write(ppp_dev_fd, data, sizeof(data));
    printf("write ret = %d\n", ret);
    
    // notify detector
    if (write(pipe_fd[1], &x, 1) < 0) {
        errExit("write");
    }
    
    wait(NULL);
    return 0;
}