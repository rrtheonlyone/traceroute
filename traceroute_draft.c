/*
 * CS3103 Assignment 2 Part C
 * Name: Rahul Rajesh
 * Matric Number: A0168864L
 */


// Traceroute implementation in C
// refer to README file for information on running

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

void usage();

    unsigned short /* this function generates header checksums */
csum (unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

const int PORT = 4550;
const int MX_LEN = 1024;

int main(int argc, char *argv[])
{
    srand ( time(NULL) );
    if (argc != 2) {
        usage();
        return 1;
    }


    //create a TCP socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("error creating socket");
        return 1;
    }

    unsigned char packet[MX_LEN];
    memset(packet, 0, MX_LEN);
    for (int i = 0; i < 40; i++) {
        printf("%02x ", packet[i]);
        if (i && i % 10 == 0) printf("\n");
    }
    printf("\n");

    struct tcphdr* tcph = malloc(sizeof(struct tcphdr));
    struct ip* iph = (struct ip*)packet;

    iph->ip_v = 4; //version
    iph->ip_hl = 5; //length in 32 bit increments
    iph->ip_tos = 0; //type of service (pretty useless field I think)

    //total length including upper layer headers
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);

    //identifier for fragmentation - also consider byte order
    iph->ip_id = htons(0);

    //no fragmentation of course
    iph->ip_off = 0;

    //we will play around with this value
    iph->ip_ttl = 3;

    //we will TCP project want
    iph->ip_p = IPPROTO_TCP;

    //we will set the address
    //iph->ip_src = 0;
    iph->ip_src.s_addr = 0;
    iph->ip_dst.s_addr = inet_addr(argv[1]);

    //checksum (leave blank as computer will set)
    iph->ip_sum = 0;


    //set ports accordingly?
    int xport = rand() % 50000 + 1000;
    printf("%d\n", xport);
    tcph->th_sport = htons(xport);
    tcph->th_dport = htons(PORT);

    //sequence numbers
    tcph->th_seq = 0;
    tcph->th_ack = 0;

    //header size
    tcph->th_off = 5;
    tcph->th_x2 = 0;

    //indicate connection can be closed
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(500);

    tcph->th_sum = 0;
    tcph->th_urp = 0;

    iph->ip_sum = csum ((unsigned short *) packet, iph->ip_len >> 1);

    memcpy(packet, iph, sizeof(struct ip));
    memcpy(packet + sizeof(struct ip), tcph, sizeof(struct tcphdr));


    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    sin.sin_addr.s_addr = inet_addr(argv[1]);

    //set sock options to make sure kernel doesnt automatically insert ip header
    int optval;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("cant set option on socket");
        return 1;
    }

    for (int i = 0; i < 40; i++) {
        printf("%02x ", packet[i]);
        if (i && i % 10 == 0) printf("\n");
    }
    printf("\n");

    int xs;
    if((xs = sendto(sockfd, (void*)packet, iph->ip_len, 0, (struct sockaddr*)&sin, sizeof(sin))) < 0) {
        perror("sendto failed");
        return 1;
    }

    struct ip* test = (struct ip*)packet;
    printf("%d\n", test->ip_len);
    

    printf("%d packet sent\n", xs);

    //receive 
    int sockfd2 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd2 < 0) {
        perror("Error creating reply socket");
        return 1;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(PORT);

    char buf[1000];
    socklen_t fromlen = sizeof(dest);
    if (recvfrom(sockfd2, buf, 1000, 0, (struct sockaddr*)&dest, &fromlen) < 0) {
        perror("Error recving reply");
        return 1;
    }

    struct ip* ip_reply = (struct ip*)buf;
    printf("%s\n", inet_ntoa(ip_reply->ip_src));
}

void usage()
{
    printf("Need to pass in address\n");
}

