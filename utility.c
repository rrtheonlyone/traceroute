/*
 * CS3103 Assignment 2 Part C
 * Name: Rahul Rajesh
 * Matric Number: A0168864L
 */

/*
 * A collection of useful utility functions that help
 * with dns lookup / string parsing etc.
 */

#include "traceroute.h"

//used to store text we need
char hbuf[NI_MAXHOST];

//given a host and returns ip addresses to use
//@note: function updates a global conf struct
void find_usable_addr(const char* node)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;

    struct addrinfo* res; 
    int err;
    
    if ((err = getaddrinfo(node, NULL, &hints, &res))) {
        fprintf(stderr, "name resolution error: %s\n", gai_strerror(err));
        exit(EXIT_FAILURE);
    }

    conf->dst_name = res->ai_canonname ? strdup(res->ai_canonname) : node;
    conf->dst = calloc(1, sizeof(struct sockaddr));
    memcpy(conf->dst, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
}


/*
 * A nice problem is how to not hardcode and find the right source IP to 
 * use! How do we do it? Well we dont.. we let the kernel find one for 
 * us. We do it by opening up a socket for UDP transmission and let 
 * kernel automatically bind it to an available src IP which we return.
 * 
 * Idea inspired from:
 * https://github.com/mct/tcptraceroute/blob/master/datalink.c#L281-L308
 * @note: function updates a global conf struct
 */
void find_src_addr()
{
    int s;
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in sinsrc, sindest;
    memset(&sinsrc, 0, sizeof(struct sockaddr_in)); 
    memset(&sindest, 0, sizeof(struct sockaddr_in)); 

    //TODO: we have to check ipv4/ipv6 here
    sindest.sin_addr.s_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
    
    sindest.sin_family = AF_INET;
    sindest.sin_port = htons(53); /*this doesnt matter as long as it is > 0*/

    if (connect(s, (struct sockaddr*)&sindest, sizeof(sindest)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    } 

    unsigned int size = sizeof(sinsrc);
    if (getsockname(s, (struct sockaddr *)&sinsrc, &size) < 0) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    close(s);
    conf->src = sinsrc.sin_addr.s_addr;
}

/*
 * Reverse DNS Lookup 
 */
char* find_host(char *ip_addr) {
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip_addr);
    
    socklen_t len = sizeof(struct sockaddr_in);
    if (getnameinfo((struct sockaddr *)&sin, len, hbuf, sizeof(hbuf)
                , NULL, 0, NI_NAMEREQD) != 0) {
        return NULL;
    }

    char* ret = malloc(strlen(hbuf) + 1);
    strcpy(ret, hbuf);
    return ret;
}

/*
 * Similar to finding an ip address, we attempt to open 
 * a TCP socket to let the kernel find an unused port from
 * us. We also pass in a requested port that will be given
 * if it is available
 * @note: function updates a global conf struct
 */
void find_unused_port(u_short req)
{
    int s;
    if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in in;
    unsigned int sz = sizeof(in);

    in.sin_family = AF_INET;
    in.sin_port = htons(req);

    if (bind(s, (struct sockaddr*)&in, sz) < 0) {
        perror("cannot bind to any port");
        exit(EXIT_FAILURE);
    }

    if (getsockname(s, (struct sockaddr*)&in, &sz) < 0) {
        perror("get sockname");
        exit(EXIT_FAILURE);   
    }

    close(s);
    conf->src_port = ntohs(in.sin_port);
}

/*
 * finds the relevant interface for the IP address 
 * we have chosen
 * @note: function updates a global conf struct
 */
void find_device() 
{
    struct ifaddrs *ifaddr;
    char* dev = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    struct ifaddrs *ifa;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        u_long s1 = ((struct sockaddr_in*) ifa->ifa_addr)->sin_addr.s_addr;
        if (conf->src && s1 == conf->src) {
            dev = ifa->ifa_name;
        }
    }

    if (!dev) {
        return;
    }

    conf->device = dev;
}

//given a long address, returns an IP string
char* ip_to_str(u_long addr) 
{
    struct in_addr ip_addr;
    ip_addr.s_addr = addr;

    char* res = inet_ntoa(ip_addr);
    char* buffer = malloc(strlen(res) + 5);
    strcpy(buffer, res);

    return buffer; 
}

//calculates time delta in ms 
double time_diff(struct timeval* t1, struct timeval *t2) 
{
    return (double)(t2->tv_sec - t1->tv_sec) * 1000.0 +
        (double)(t2->tv_usec - t1->tv_usec) / 1000.0;
}

//checks if given string is a number
int check_numeric(char* s) {
    int is_number = 0;
    for (size_t i = 0; i < strlen(s); i++) {
        is_number |= isdigit(s[i]);
    }
    return is_number;
}

