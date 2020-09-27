#include "traceroute.h"

//builds a raw syn packet for distribution
size_t build_syn_packet(u_char* packet, uint32_t src, uint32_t dst, uint16_t id, 
        uint8_t ttl, uint16_t sp ,uint16_t dp)
{
    size_t datalen = sizeof(struct ip) + sizeof(struct tcphdr);
    build_ip_packet(
        packet,
        datalen,                                     /* Total Length */
        0,                                           /* TOS */
        htons(id),                                   /* identifier */
        0,                                           /* Frag Offset */
        ttl,                                         /* TTL */
        IPPROTO_TCP,                                 /* Protocol */
        src,                                         /* IP Source */
        dst,                                         /* IP Dest */
        NULL,                                        /* Payload */
        0                                            /* Payload Size */
    );

    build_tcp_packet(
        packet,                                     
        sp,          /* Source Port */
        dp,          /* Dest Port */
        0,           /* Seq Num */
        0,           /* Ack Num */
        TH_SYN,      /* Control Flag */
        0,           /* Window */
        0,           /* Urgent? */
        NULL,        /* Payload */
        0            /* Payload Size */
    );

    return datalen;
}

//dumps packet for debugging
void dump_packet(u_char* packet, int len)
{
    u_char *p = packet;
    fprintf(stderr, "packet: ");
    for (int i = 0; i < len; ++i) {
        if ((i % 24) == 0) {
            fprintf(stderr, "\n ");
        }

        fprintf(stderr, " %02x", *p);
        p++;
    } 
    fprintf(stderr, "\n");
}

int packet_ok(u_char* buffer, struct pcap_pkthdr* pkt_hdr, struct record* log)
{
    size_t mn = sizeof(struct ip) + sizeof(struct ether_header);
    if (pkt_hdr->caplen < mn) {
        return -1;
    } 

    struct ip *ip_hdr = (struct ip*)(buffer + sizeof(struct ether_header));

    //basic checks on ip header
    if (ip_hdr->ip_v != 4 
            || ip_hdr->ip_hl > 5
            || ip_hdr->ip_dst.s_addr != conf->src) {
        return -1;
    }

    //we only care about TCP ACK or ICMP reply
    if (ip_hdr->ip_p != IPPROTO_ICMP && ip_hdr->ip_p != IPPROTO_TCP) {
        return -1;
    }

    int status = 0;

    //let's check for ICMP first
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        const size_t offset = 8;
        struct icmp *icmp_hdr = (struct icmp*)(buffer + sizeof(struct ip) 
                + sizeof(struct ether_header));
        struct ip* old_hdr = (struct ip*)(buffer + sizeof(struct ip) 
                + sizeof(struct ether_header) + offset);

        uint16_t* src_port = (uint16_t*)(((u_char*)old_hdr) + sizeof(struct ip));
        uint16_t* dst_port = (uint16_t*)(((u_char*)old_hdr) + sizeof(struct ip) + 2);

        //check payload matches with our record
        if (ntohs(old_hdr->ip_id) != log->id 
                || old_hdr->ip_p != IPPROTO_TCP
                || old_hdr->ip_src.s_addr != conf->src
                || conf->src_port != ntohs(*src_port) 
                || conf->dst_port != ntohs(*dst_port)) {
            return -1;
        }        

        //if unreachable, we mark as done 
        if (icmp_hdr->icmp_type == ICMP_UNREACH) {
            //can do some further logging here based on status
            status = 1;
        }
    }

    //check if we have TCP ACK 
    if (ip_hdr->ip_p == IPPROTO_TCP) {

        //ignore if not from our intended destination
        uint32_t d_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
        if (ip_hdr->ip_src.s_addr != d_addr) {
            return -1;
        }

        struct tcphdr *tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr 
                + sizeof(struct ip));
       
        if (ntohs(tcp_hdr->th_sport) != conf->dst_port
                || ntohs(tcp_hdr->th_dport) != conf->src_port) {
            return -1;
        }

        status = 1;
    }
 
    //update record since its our packet
    log->dnat_ip = inet_ntoa(ip_hdr->ip_src);
    log->addr = find_host(log->dnat_ip);
    
    struct timeval rcv_time;
    if (gettimeofday(&rcv_time, NULL) < 0) {
        perror("get time failed");
        exit(EXIT_FAILURE);
    }
    
    log->delta_time = time_diff(&log->timestamp, &pkt_hdr->ts); 
    return status; 
}

//forms tcp packet and writes into buffer
void build_tcp_packet(u_char* packet, uint16_t sp, uint16_t dp, uint32_t seq, 
        uint32_t ack, uint8_t control, uint16_t win, uint16_t urg, 
        const uint8_t *payload, uint32_t payload_s) 
{
    struct tcphdr *tcp_header = (struct tcphdr*) (packet + sizeof(struct ip));

    tcp_header->th_sport = htons(sp);
    tcp_header->th_dport = htons(dp);
    tcp_header->th_seq = htonl(seq);
    tcp_header->th_ack = htonl(ack);
    tcp_header->th_flags = control;
    tcp_header->th_x2 = 0;
    tcp_header->th_off = 5;

    tcp_header->th_win = htons(win);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = htons(urg);

    tcp_header->th_sum = tcp_chksum(packet); 
}

//forms ip packet and writes into buffer
void build_ip_packet(u_char* packet, uint16_t ip_len, uint8_t tos, uint16_t id, 
        uint16_t frag,uint8_t ttl, uint8_t prot, uint32_t src, uint32_t dst,
        const uint8_t *payload, uint32_t payload_s)
{
    struct ip *ip_header = (struct ip*) packet; 

    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = tos;
    ip_header->ip_len = ip_len;
    ip_header->ip_id = id;
    ip_header->ip_off = frag;
    ip_header->ip_ttl = ttl;
    ip_header->ip_p = prot;
    ip_header->ip_src.s_addr = src;
    ip_header->ip_dst.s_addr = dst;
    ip_header->ip_sum = 0;

    //calculate right check sum
    ip_header->ip_sum = in_chksum(packet, sizeof(struct ip));
}

//calc checksum for ip headers
u_short in_chksum(u_char *addr, int len)
{
    u_short *p = (u_short*)addr;
    int cnt = len;

    int sum = 0;
    while (cnt > 1) {
        sum += *p;
        p++;
        cnt -= 2;
    }

    //odd byte left, so add it in
    if (cnt == 1) {
        sum += *(u_char *)p;
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return ((unsigned short)~sum);
}

//calc checksum for tcp segment (with pseudoheader)
u_short tcp_chksum(u_char *addr) {
    struct ip* ip_hdr = (struct ip*) addr;
    struct tcphdr* tcp_hdr = (struct tcphdr*)(addr + sizeof(struct ip));

    //add pseudo header
    struct pseudo_header {
        struct in_addr src;
        struct in_addr dest;
        u_char padding;
        u_char protocol;
        u_short length;
    } ph;

    ph.src = ip_hdr->ip_src;
    ph.dest = ip_hdr->ip_dst;
    ph.padding = 0;
    ph.protocol = ip_hdr->ip_p;
    ph.length = htons(sizeof(struct tcphdr));

    size_t len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
  
    u_char *psuedo_pkt = malloc(len);
    if (psuedo_pkt == NULL) {
        perror("error in allocation");
        exit(EXIT_FAILURE);
    }

    memcpy(psuedo_pkt, &ph, sizeof(ph));
    memcpy(psuedo_pkt + sizeof(ph), tcp_hdr, sizeof(struct tcphdr));
    return in_chksum(psuedo_pkt, len);
}

