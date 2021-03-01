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

int set_flow_label(int sock, struct sockaddr_in6 *sa6P, int flowlabel)
{
    char freq_buf[sizeof(struct in6_flowlabel_req)];
    struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)freq_buf;
    int freq_len = sizeof(*freq);

    memset(freq, 0, sizeof(*freq));
    freq->flr_label = htonl(flowlabel & IPV6_FLOWINFO_FLOWLABEL);
    freq->flr_action = IPV6_FL_A_GET;
    freq->flr_flags = IPV6_FL_F_CREATE;
    freq->flr_share = IPV6_FL_S_ANY;
    memcpy(&freq->flr_dst, &sa6P->sin6_addr, 16);

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, freq_len) < 0) {
        printf("setsockopt: %s\n", strerror(errno));
        return 1;
    }
    sa6P->sin6_flowinfo = freq->flr_label;
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
    printf("Remote Label 0x%x\n", ntohl(freq.flr_label));
    return freq.flr_label;
}


int main(int argc, char *argv[]) {
    int sockfd;
    char buffer[MAXLINE];
    char *hello = "Hello from client";
    struct sockaddr_in6     servaddr;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, argv[1], &servaddr.sin6_addr);
    servaddr.sin6_port = htons(PORT);

    // Flow label
    enable_flow_label(sockfd);
    set_flow_label(sockfd, &servaddr, 255);
    servaddr.sin6_flowinfo = htonl(255 & IPV6_FLOWINFO_FLOWLABEL);
    printf("flow label - 0x%x\n", (255 & IPV6_FLOWINFO_FLOWLABEL));

    int n, len;

    sendto(sockfd, (const char *)hello, strlen(hello),
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
    printf("Hello message sent.\n");
    get_flow_labels(sockfd);
    get_remote_flow_label(sockfd);

    n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                MSG_WAITALL, (struct sockaddr *) &servaddr,
                &len);
    buffer[n] = '\0';
    printf("Server : %s\n", buffer);
    set_flow_label(sockfd, &servaddr, 254);
    servaddr.sin6_flowinfo = htonl(254 & IPV6_FLOWINFO_FLOWLABEL);
    printf("flow label - 0x%x\n", (254 & IPV6_FLOWINFO_FLOWLABEL));
        sendto(sockfd, (const char *)hello, strlen(hello),
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,
            sizeof(servaddr));
    printf("Hello message sent.\n");
    get_flow_labels(sockfd);
    get_remote_flow_label(sockfd);

    n = recvfrom(sockfd, (char *)buffer, MAXLINE,
                MSG_WAITALL, (struct sockaddr *) &servaddr,
                &len);
    buffer[n] = '\0';
    printf("Server : %s\n", buffer);

    close(sockfd);
    return 0;
}