//
// Created by Marian Babik on 11/18/20.
//
#include<stdio.h>
#include<string.h>	//strlen
#include<stdlib.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<unistd.h>	//write
#include<pthread.h> //for threading , link with lpthread
#include <linux/in.h>
#include <linux/in6.h>
#include <errno.h>

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
    return 0;
}

//the thread function
void *connection_handler(void *);

int main(int argc , char *argv[])
{
    int socket_desc , client_sock , c , *new_sock, flag;
    struct sockaddr_in6 server_addr, client_addr;
    socklen_t client_addr_len;
    char str_addr[INET6_ADDRSTRLEN];

    //Create socket
    socket_desc = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("socket created");
    flag = 1;
    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

    //Prepare the sockaddr_in structure
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(24999);

    //Bind
    if( bind(socket_desc,(struct sockaddr*)&server_addr , sizeof(server_addr)) < 0)
    {
        //print the error message
        perror("bind() failed.");
        return 1;
    }
    puts("bind done");

    //Listen
    listen(socket_desc , 10);

    //Accept and incoming connection
    puts("waiting for incoming connections...");
    c = sizeof(struct sockaddr_in6);


    //Accept and incoming connection
    client_addr_len = sizeof(client_addr);
    while( (client_sock = accept(socket_desc, (struct sockaddr*)&client_addr, &client_addr_len) ))
    {
        inet_ntop(AF_INET6, &(client_addr.sin6_addr),
                  str_addr, sizeof(str_addr));
        printf("new connection from: %s:%d ...\n",
               str_addr,
               ntohs(client_addr.sin6_port));

        pthread_t sniffer_thread;
        new_sock = malloc(1);
        *new_sock = client_sock;

        if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0)
        {
            perror("could not create thread");
            return 1;
        }

        //Now join the thread , so that we dont terminate before the thread
        //pthread_join( sniffer_thread , NULL);
        puts("handler assigned");
    }

    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }

    return 0;
}

/*
 * This will handle connection for each client
 * */
void *connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char *message , client_message[2000];

    //Receive a message from client
    while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
    {
        //Send the message back to client
        write(sock , client_message , strlen(client_message));
    }

    if(read_size == 0)
    {
        puts("client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
    {
        perror("recv failed");
    }

    //Free the socket pointer
    free(socket_desc);

    return 0;
}