//
// Created by Marian Babik on 11/18/20.
//

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <errno.h>

int enable_flow_label(int sock) {
    int on = 1;

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on)) == -1) {
        printf("setsockopt(IPV6_FLOWINFO_SEND): %s\n", strerror(errno));
        return 1;
    }

    // if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO, &on, sizeof(on)) == -1) {
    //    printf("setsockopt(IPV6_FLOWINFO): %s\n", strerror(errno));
    //    return 1;
    //}
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
    sa6P->sin6_flowinfo = freq->flr_label;
    return 0;
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
        printf("Could not create socket");
        return -1;
    }
    puts("socket created");

    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, argv[1], &server_addr.sin6_addr);
    server_addr.sin6_port = htons(24999);

    puts("flow label enabled");
    set_flow_label(sock, &server_addr, 255);
    enable_flow_label(sock);

    //Connect to remote server
    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed. Error");
        return 1;
    }

    puts("connected\n");

    //keep communicating with server
    for (i = 2; i < 12; ++i) {
        sprintf(message, "test message # %d", i);
        // set_flow_label(sock, &server_addr, i);
        //Send some data
        if (send(sock, message, strlen(message), 0) < 0) {
            puts("send failed");
            return 1;
        }

        //Receive a reply from the server
        if (recv(sock, server_reply, 2000, 0) < 0) {
            puts("recv failed");
            break;
        }

        puts("server replied:");
        puts(server_reply);
        sleep(2);
    }

    close(sock);
    return 0;
}