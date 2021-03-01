#include <linux/in6.h>
#include<stdio.h>
#include<string.h>	
#include<stdlib.h>	
#include<sys/socket.h>
#include<arpa/inet.h>	
#include<unistd.h>	
#include<pthread.h> 
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
    printf("Remote Label 0x%x\n", freq.flr_label);
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

int get_tclass(int sockfd)
{
    int tclass = 0;
    getsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, tclass, sizeof(tclass);
    return tclass;
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
    enable_flow_label(socket_desc);

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
	    enable_flow_label(client_sock);
	    enable_tclass(client_sock);
        get_remote_flow_label(client_sock);

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
    int optval;
    socklen_t optlen = sizeof(optval);

    //Receive a message from client
    while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
    {
        //Send the message back to client
        get_flow_labels(sock);
        get_remote_flow_label(sock);
	set_tclass(sock, 252);
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