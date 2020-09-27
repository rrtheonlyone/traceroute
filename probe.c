#include "traceroute.h"

const int SYN_PK_SIZE = 100;

char hbuf[NI_MAXHOST];
u_char packet[SYN_PK_SIZE];

// main driver that prepares sockets and sends TCP syn out
void probe(struct record *log) 
{
    memset(packet, 0, sizeof(packet));
    log->id = rand() & ((1 << 16) - 5);

    uint32_t d_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
    size_t datalen = build_syn_packet(
        packet,
        conf->src,
        d_addr,
        log->id,
        log->ttl,
        conf->src_port,
        conf->dst_port
    );

    if (gettimeofday(&(log->timestamp), NULL) < 0) {
        perror("get time failed");
        exit(EXIT_FAILURE);
    }

    if (sendto(send_sck, packet, datalen, 0, conf->dst, conf->dst->sa_len) < 0) {
        perror("sending failed");
        exit(EXIT_FAILURE);
    }
}

int capture(const u_char** buffer, struct pcap_pkthdr** pkt_hdr, int timeout)
{
    struct pollfd pfd[1];
    int ok = 0;

    pfd[0].fd = pcap_sck;
    pfd[0].events = POLLIN;
    pfd[0].revents = 0;

    if (poll(pfd, 1, timeout) > 0) {
        ok = pcap_next_ex(pcap, pkt_hdr, buffer);
    }

    return ok;
}

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
    if (res->ai_next) {
        if (getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf),
                    NULL, 0, NI_NUMERICHOST) != 0) {
            strlcpy(hbuf, "?", sizeof(hbuf));
        }
        printf("Warning: %s has multiple addresses; using %s\n", 
                conf->dst_name, hbuf); 
    }

    conf->dst = calloc(1, sizeof(struct sockaddr));
    memcpy(conf->dst, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
}

//https://github.com/mct/tcptraceroute/blob/master/datalink.c#L281-L308
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

char* ip_to_str(u_long addr) 
{
    struct in_addr ip_addr;
    ip_addr.s_addr = addr;

    char* res = inet_ntoa(ip_addr);
    char* buffer = malloc(strlen(res) + 5);
    strcpy(buffer, res);

    return buffer; 
}

double time_diff(struct timeval* t1, struct timeval *t2) 
{
    return (double)(t2->tv_sec - t1->tv_sec) * 1000.0 +
        (double)(t2->tv_usec - t1->tv_usec) / 1000.0;
}

