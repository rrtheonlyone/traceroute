/*
 * CS3103 Assignment 2 Part C
 * Name: Rahul Rajesh
 * Matric Number: A0168864L
 */

/*
 * This file helps to send packets out and capture them back 
 */
#include "traceroute.h"

//we write the packet data into here
u_char packet[SYN_PK_SIZE];

//send empty SYN packet and store info into log
void probe(struct record *log) 
{
    memset(packet, 0, sizeof(packet));

    //we pick a random id for the packet 
    //prob of collision is pretty low I would think
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

//capture data with a timeout
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

