#include <linux/in6.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>

#define PORT    24999
#define MAXLINE 1024

size_t recvfrom2(int fd, char *buf, size_t len, int flags,
                struct sockaddr *addr, int *addrlen)
{
  size_t cc;
  char cbuf[128];
  struct cmsghdr *c;
  struct iovec iov = { buf, len };
  struct msghdr msg = { addr, *addrlen,
                        &iov,  1,
                        cbuf, sizeof(cbuf),
                        0 };

  cc = recvmsg(fd, &msg, flags);
  if (cc < 0)
    return cc;
  ((struct sockaddr_in6*)addr)->sin6_flowinfo = 0;
  *addrlen = msg.msg_namelen;
  for (c=CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
    if (c->cmsg_level != SOL_IPV6 ||
      c->cmsg_type != IPV6_FLOWINFO)
        continue;
    ((struct sockaddr_in6*)addr)->sin6_flowinfo = *(__u32*)CMSG_DATA(c);
  }
  return cc;
}


int enable_flow_label(int sock)
{
    int on = 1;

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on)) == -1) {
        printf("setsockopt(IPV6_FLOWINFO_SEND): %s\n", strerror(errno));
        return 1;
    }

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO, &on, sizeof(on)) == -1) {
        printf("setsockopt(IPV6_FLOWINFO): %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

int get_flow_labels(int sockfd)
{
    int s;
    struct in6_flowlabel_req freq;
    int size = sizeof(freq);
    freq.flr_action = IPV6_FL_A_GET;
    getsockopt(sockfd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &freq, &size);
    printf("Local Label %05X share %d expires %d linger %d\n", ntohl(freq.flr_label), freq.flr_share,
                                                         freq.flr_linger, freq.flr_expires);
    return 0;
}

unsigned int get_remote_flow_label(int sockfd)
{
    int s;
    struct in6_flowlabel_req freq;
    int size = sizeof(freq);
    freq.flr_action = IPV6_FL_F_REMOTE;
    getsockopt(sockfd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &freq, &size);
    printf("Remote Label 0x%x\n", freq.flr_label);
    return freq.flr_label;
}

int main() {
    int sockfd;
    char buffer[MAXLINE];
    char *hello = "Hello from server";
    struct sockaddr_in6 servaddr, cliaddr;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin6_family    = AF_INET6; // IPv4
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(PORT);

    enable_flow_label(sockfd);
    // Bind the socket with the server address
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,
            sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int len, n;

    len = sizeof(cliaddr);  //len is value/resuslt

    n = recvfrom2(sockfd, (char *)buffer, MAXLINE,
                MSG_WAITALL, ( struct sockaddr *) &cliaddr,
                &len);
    get_flow_labels(sockfd);
    get_remote_flow_label(sockfd);
    printf("Label from socket: 0x%x\n", cliaddr.sin6_flowinfo);
    buffer[n] = '\0';
    printf("Client : %s\n", buffer);
    sendto(sockfd, (const char *)hello, strlen(hello),
        MSG_CONFIRM, (const struct sockaddr *) &cliaddr,
            len);
    printf("Hello message sent.\n");
    n = recvfrom2(sockfd, (char *)buffer, MAXLINE,
                MSG_WAITALL, ( struct sockaddr *) &cliaddr,
                &len);
    get_flow_labels(sockfd);
    get_remote_flow_label(sockfd);
    printf("Label from socket: 0x%x\n", cliaddr.sin6_flowinfo);
    buffer[n] = '\0';
    printf("Client : %s\n", buffer);
    sendto(sockfd, (const char *)hello, strlen(hello),
        MSG_CONFIRM, (const struct sockaddr *) &cliaddr,
            len);
    printf("Hello message sent.\n");

    return 0;
}