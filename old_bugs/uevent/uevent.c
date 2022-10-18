#define _GNU_SOURCE
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                            } while (0)
// https://backreference.org/2010/03/26/tuntap-interface-tutorial/
// alloc tun/tap device
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */

   /* open the clone device */
   if( (fd = open(clonedev, O_RDWR)) < 0 ) {
       errExit("open fd");
   }

   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

   if (*dev) {
     /* if a device name was specified, put it in the structure; otherwise,
      * the kernel will try to allocate the "next" device of the
      * specified type */
     strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }

   /* try to create the device */
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
       errExit("tun ioctl");
   }

  /* if the operation was successful, write back the name of the
   * interface to the variable "dev", so the caller can know
   * it. Note that the caller MUST reserve space in *dev (see calling
   * code below) */
  strcpy(dev, ifr.ifr_name);

  /* this is the special file descriptor that the caller will use to talk
   * with the virtual interface */
  return fd;
}

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

void set_flag(const char *ifn, short int flag) {
    int s = open_netlink();
    struct {
        struct nlmsghdr n;
        struct ifinfomsg r;
    } nl_request;
    memset(&nl_request, 0, sizeof(nl_request));
    nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nl_request.n.nlmsg_flags = NLM_F_REQUEST;
    nl_request.n.nlmsg_type = RTM_NEWLINK;
    nl_request.r.ifi_flags = flag;
    nl_request.r.ifi_index = if_nametoindex(ifn);
    nl_request.r.ifi_change = flag;
    if (send(s, &nl_request, nl_request.n.nlmsg_len, 0) < 0) {
        errExit("send");
    }
}

void set_ipv4(const char *ifn, const char *ip, int prefixlen) {
    int s = open_netlink();
    if (s < 0) {
        errExit("socket");
    }
    struct {
        struct nlmsghdr n;
        struct ifaddrmsg r;
        char buf[256];
    } nl_request;
    memset(&nl_request, 0, sizeof(nl_request));
    nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nl_request.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nl_request.n.nlmsg_type = RTM_NEWADDR;
    nl_request.r.ifa_family = AF_INET;
    nl_request.r.ifa_index = if_nametoindex(ifn);
    nl_request.r.ifa_prefixlen = prefixlen;
    int ip_addr = inet_addr(ip);
    rtattr_add(&nl_request.n, sizeof(nl_request), IFA_LOCAL, &ip_addr, 4);
    rtattr_add(&nl_request.n, sizeof(nl_request), IFA_ADDRESS, &ip_addr, 4);
    if (send(s, &nl_request, nl_request.n.nlmsg_len, 0) < 0) {
        errExit("send");
    }
}

unsigned short checksum(unsigned short* buff, int _16bitword)
{
    unsigned long sum;
    for (sum = 0; _16bitword > 0; _16bitword--)
        sum += *(buff)++;
    sum = ((sum >> 16) + (sum & 0xFFFF));
    sum += (sum>>16);
    return (unsigned short)(~sum);
}

static bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		int err = errno;
		close(fd);
		errno = err;
		return false;
	}
	close(fd);
	return true;
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
    // set value here since kernel incorrectly refer to init_net
    if (write_file("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "0") == false) {
        errExit("disable ignoring icmp multicast");
    }
    // system("mount -t sysfs sysfs /sys");
    
    int pid = fork();
    if (pid < 0) {
        errExit("fork");
    }
    if (pid == 0) {
        close(pipe_fd[1]);
        close(pipe_fd1[0]);
            int nl_socket;
        struct sockaddr_nl src_addr;
        char msg[4096];
        int ret;

        // Prepare source address
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();
        src_addr.nl_groups = -1;

        nl_socket = socket(AF_NETLINK, (SOCK_DGRAM | SOCK_CLOEXEC), NETLINK_KOBJECT_UEVENT);
        if (nl_socket < 0) {
            errExit("create netlink socket");
        }

        ret = bind(nl_socket, (struct sockaddr*) &src_addr, sizeof(src_addr));
        if (ret < 0) {
            errExit("bind netlink");
        }

        printf("Waiting for events now...\n");
        while(1) {
            int r = recv(nl_socket, msg, sizeof(msg), MSG_DONTWAIT);
            if (r < 0) {
                continue;
            }
            printf("length:%i\n msg:%s", r, msg);
            if (write(pipe_fd1[1], &x, 1) < 0) {
                errExit("write");
            }
            break;
        }
        return 0;
    }
    close(pipe_fd[0]);
    close(pipe_fd1[1]);
    
    sleep(1);
    if (unshare(CLONE_NEWNET | CLONE_NEWNS) < 0) {
        errExit("unshare");
    }

    char tun_name[IFNAMSIZ];
    strcpy(tun_name, "tun0");
    int tunfd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
    set_ipv4(tun_name, "172.16.1.1", 24);
    set_flag(tun_name, IFF_UP);
    // wait for init_net receive uevent
    if (read(pipe_fd1[0], &x, 1) < 0) {
        errExit("read");
    }

    wait(NULL);
    return 0;
}