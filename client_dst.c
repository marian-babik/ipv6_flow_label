#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

int main(int argc, char *argv[])
{
    int fd;
    struct sockaddr_in6 srv_addr;
    struct hostent *srv;
    char cli_msg[] = "This is a string from client!";
    void *ext_hdr_p;
    size_t ext_hdr_size;
    dst_opt_tlv_t opt;

    if (argc < 3) {
        printf("Usage: %s <srv> <port>\n", argv[0]);
        exit(0);
    }

    printf("IPv6 TCP client started...\n");

    //create IPv6/TCP socket
    if ((fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
        print_error("ERROR - socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)");

    if (!(srv = gethostbyname2(argv[1], AF_INET6)))
        print_error_h("ERROR - gethostbyname2(argv[1], AF_INET6)");

    memset((char *)&srv_addr, 0, sizeof(srv_addr));
    memcpy((char *)&srv_addr.sin6_addr.s6_addr, (char *)srv->h_addr, srv->h_length);

    srv_addr.sin6_flowinfo = 0;
    srv_addr.sin6_family = AF_INET6;
    srv_addr.sin6_port = htons(atoi(argv[2]));

    //prepare the "data" for dst_opt option data and pad
    memset((void *)&opt, 0, sizeof(opt));
    opt.data.port = htons(0x80);
    opt.data.vrf = htons(0x11);
    opt.pad.padn = 0x1;
    opt.pad.len = 0x2;

    int i;
    for (i = 0; i < sizeof(opt.data.addr8); i++)
        opt.data.addr8[i] = 0x0 + i;

    printf("\nAncilary data for server:\n");
    print_option_data(&opt);

    //prepare the buffer
    ext_hdr_p = prepare_buff(0x1f, (const char const *)&opt, sizeof(opt), &ext_hdr_size);

    printf("\nWritten dst_opts extension header:\n");
    printf("size %d [", (int)ext_hdr_size);
    print_hex_data((unsigned char *)ext_hdr_p, ext_hdr_size);
    printf("\b]\n");

    //introduce the ext header to the ipv6 stack
    if ((setsockopt(fd, IPPROTO_IPV6, IPV6_DSTOPTS, ext_hdr_p, ext_hdr_size)) == -1)
        print_error("ERROR - setsockopt(fd, IPPROTO_IPV6, IPV6_DSTOPTS, ext_hdr_p, ext_hdr_size)");

    //connect to the srv
    if (connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
        print_error("ERROR - connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr))");

    printf("\nConnected to %s:%d\n", srv->h_name, atoi(argv[2]));

    //send a msg to the srv - intentionally ignore partial send for brevity
    if(send(fd, cli_msg, sizeof(cli_msg), 0) == -1)
        print_error("ERROR - send(fd, cli_msg, sizeof(cli_msg), 0)");
    printf("Sent %d Bytes [%s]\n", (int)sizeof(cli_msg), cli_msg);

    //clean up after yourself
    printf("Exiting ...\n");
    close(fd);
    free(ext_hdr_p);
    return 0;
}