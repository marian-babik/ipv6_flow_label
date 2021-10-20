#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "util.h"

int main(int argc, char *argv[])
{
    int l_fd, c_fd, recv_data_size;
    char cli_msg[MAX_MSG_LEN];
    struct sockaddr_in6 srv_addr, cli_addr;
    char client_addr_ipv6[INET6_ADDRSTRLEN];
    int enable;
    socklen_t size;
    char ext_hdr[10240];
    socklen_t ext_hdr_size;
    dst_opt_tlv_t opt;

    printf("IPv6 TCP Server Started...\n");

    //create srv socket
    if ((l_fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
        print_error("ERROR - socket(AF_INET6, SOCK_STREAM, 0)");

    memset((void *)&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin6_family = AF_INET6;
    srv_addr.sin6_addr = in6addr_any;
    srv_addr.sin6_port = htons(atoi(argv[1]));

    //bind to the port
    if (bind(l_fd, (struct sockaddr *)&srv_addr, (socklen_t)sizeof(srv_addr)) == -1)
        print_error("ERROR - bind(l_fd, (struct sockaddr *)&srv_addr, (socklen_t)sizeof(srv_addr))");

    //create listen socket with backlog of 5
    if (listen(l_fd, 5) == -1)
        print_error("listen(l_fd, 5)");

    //set up listening socket properties
    enable = 1;
    if (setsockopt(l_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1)
        print_error("ERROR - setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable))");

    enable = 1;
    if (setsockopt(l_fd, IPPROTO_IPV6, IPV6_RECVDSTOPTS, &enable, (socklen_t)sizeof(enable)) == -1)
        print_error("ERROR - setsockopt(l_fd, IPPROTO_IPV6, IPV6_DSTOPTS, &enable, (socklen_t)sizeof(enable))");

    printf("Waiting for client ...\n");

    //wait for the client
    size = (socklen_t)sizeof(cli_addr);
    if ((c_fd = accept(l_fd, (struct sockaddr *)&cli_addr, &size)) == -1)
        print_error("ERROR - accept(l_fd, (struct sockaddr *)&cli_addr, &clilen)");

    if (inet_ntop(AF_INET6, &(cli_addr.sin6_addr), client_addr_ipv6, (socklen_t)sizeof(client_addr_ipv6)))
        printf("Incoming connection from client having IPv6 address: %s\n", client_addr_ipv6);
    else
        print_error("ERROR - inet_ntop(AF_INET6, &(cli_addr.sin6_addr), client_addr_ipv6, (socklen_t)sizeof(client_addr_ipv6))");

    //recv msg from the client
    memset(cli_msg, 0, sizeof(cli_msg));
    if ((recv_data_size = recv(c_fd, (void *)cli_msg, 30, 0)) == -1)
        print_error("ERROR - recv(c_fd, (void *)cli_msg, sizeof(cli_msg) - 1, 0)");

    printf("\nReceived msg from client:\n");
    printf(" %dB [%s]\n", recv_data_size, cli_msg);

    //get ipv6 extension header
    ext_hdr_size = (socklen_t)sizeof(ext_hdr);
    if ((getsockopt(c_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, (void *)ext_hdr, &ext_hdr_size)) == -1)
        print_error("ERROR - getsockopt(c_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, ext_hdr_p, &ext_hdr_size)");

    if (ext_hdr_size)
    {
        //print raw ancilary data
        printf("\nAncilary data from client:\n");
        printf("Raw data:\n0x%02xB [", ext_hdr_size);
        print_hex_data((unsigned char *)ext_hdr, ext_hdr_size);
        printf("\b]\n");

        //parse them
        memset((void *)&opt, 0, sizeof(opt));
        find_option_data(&opt, ext_hdr, 0x1f);

        //print them out
        print_option_data(&opt);
    }
    else
        printf("No extension header data received!!!\n");

    //recv msg from the client
    memset(cli_msg, 0, sizeof(cli_msg));
    if ((recv_data_size = recv(c_fd, (void *)cli_msg, sizeof(cli_msg) - 1, 0)) == -1)
        print_error("ERROR - recv(c_fd, (void *)cli_msg, sizeof(cli_msg) - 1, 0)");

    printf("\nReceived msg from client:\n");
    printf(" %dB [%s]\n", recv_data_size, cli_msg);

    //get ipv6 extension header
    ext_hdr_size = (socklen_t)sizeof(ext_hdr);
    if ((getsockopt(c_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, (void *)ext_hdr, &ext_hdr_size)) == -1)
        print_error("ERROR - getsockopt(c_fd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, ext_hdr_p, &ext_hdr_size)");

    if (ext_hdr_size)
    {
        //print raw ancilary data
        printf("\nAncilary data from client:\n");
        printf("Raw data:\n0x%02xB [", ext_hdr_size);
        print_hex_data((unsigned char *)ext_hdr, ext_hdr_size);
        printf("\b]\n");

        //parse them
        memset((void *)&opt, 0, sizeof(opt));
        find_option_data(&opt, ext_hdr, 0x1f);

        //print them out
        print_option_data(&opt);
    }
    else
        printf("No extension header data received!!!\n");

    //clean up after yourself
    printf("Exiting ...\n");
    close(l_fd);
    close(c_fd);
    return 0;
}
