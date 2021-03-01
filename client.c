#include <linux/in6.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

int enable_flow_label(int sock) {
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

int set_flow_label(int sock, struct sockaddr_in6 *sa6P, int flowlabel) {
    char freq_buf[sizeof(struct in6_flowlabel_req)];
    struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *) freq_buf;
    int freq_len = sizeof(*freq);

    memset(freq, 0, sizeof(*freq));
    freq->flr_label = htonl(flowlabel & IPV6_FLOWINFO_FLOWLABEL);
    printf("flow label - 0x%x\n", (flowlabel & IPV6_FLOWINFO_FLOWLABEL));
    freq->flr_action = IPV6_FL_A_GET;
    freq->flr_flags = IPV6_FL_F_CREATE;
    freq->flr_share = IPV6_FL_S_ANY;
    memcpy(&freq->flr_dst, &sa6P->sin6_addr, 16);

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, freq_len) < 0) {
        printf("setsockopt: %s\n", strerror(errno));
        return 1;
    }
    // sa6P->sin6_flowinfo = freq->flr_label;
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
    printf("Remote Label %05X\n", ntohl(freq.flr_label));
    return freq.flr_label;
}

void enable_tclass(int sockfd)
{
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS,   &on, sizeof(on)) < 0 ){
        printf("setsockopt tclass enable: %s\n", strerror(errno));
    }
}

int set_tclass(int sockfd, int tclass)
{
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof(tclass)) < 0) {
        printf("setsockopt tclass: %s\n", strerror(errno));
        return 1;
    }
}

int main(int argc, char *argv[]) {
    int sock, i;
    struct sockaddr_in6 server_addr;
    char message[1000], server_reply[2000];

    if (argc != 2) {
        printf("Usage: %s ipv6_addr\n", argv[0]);
        return -1;
    }

    //Create socket
    sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        printf("Could not create socket\n");
        return -1;
    }
    printf("socket created\n");

    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, argv[1], &server_addr.sin6_addr);
    server_addr.sin6_port = htons(24999);

    printf("flow label enabled\n");
    enable_flow_label(sock);
    set_flow_label(sock, &server_addr, 255);
    server_addr.sin6_flowinfo = htonl(255 & IPV6_FLOWINFO_FLOWLABEL);

    enable_tclass(sock);
    printf("tclass: 0x%x\n", 252);
    enable_tclass(sock);
    set_tclass(sock, 252);

    //Connect to remote server
    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed. Error");
        return 1;
    }

    printf("connected\n");

    //keep communicating with server
    for (i = 2; i < 6; ++i) {
        sprintf(message, "test message # %d\n", i);
        //Send some data
        if (send(sock, message, strlen(message), 0) < 0) {
            printf("send failed");
            return 1;
        }

        //Receive a reply from the server
        if (recv(sock, server_reply, 2000, 0) < 0) {
            printf("recv failed");
            break;
        }
	    get_flow_labels(sock);
	    get_remote_flow_label(sock);

        printf("server replied:\n");
        printf(server_reply);
        sleep(2);
    }
    //try to change options while communicating
    for (i = 2; i < 6; ++i) {
        printf("tclass 0x%x\n", 140);
        set_tclass(sock, 140);
        sprintf(message, "test message # %d\n", i);
        //Send some data
        if (send(sock, message, strlen(message), 0) < 0) {
            printf("send failed\n");
            return 1;
        }

        //Receive a reply from the server
        if (recv(sock, server_reply, 2000, 0) < 0) {
            printf("recv failed\n");
            break;
        }

        printf("server replied:\n");
        printf(server_reply);
        sleep(2);
    }

    close(sock);
    return 0;
}