#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <poll.h>
#include <net/ethernet.h>
#include <pcap.h>

struct config {
    uint32_t src;
    const char* dst_name;
    struct sockaddr* dst;
    uint16_t dst_port;
    uint16_t src_port;
    int max_ttl;
    int nqueries;
    int timeout;
    char* device;
};

struct record {
    int ttl;
    int q;
    u_short id;
    struct timeval timestamp;
    double delta_time;
    char *addr, *dnat_ip;
};

#define MX_PKT 500
#define MX_TEXT 500

extern pcap_t* pcap;
extern struct config* conf;
extern int send_sck;
extern int rcv_sck;
extern int pcap_sck;

void start_pcap_listener();

void probe(struct record *log); 
int capture(const u_char** buffer, struct pcap_pkthdr** pkt_hdr, int timeout);
int packet_ok(u_char* buffer, struct pcap_pkthdr* pkt_hdr, struct record* log);

void find_usable_addr(const char* node);
void find_src_addr(void);
void find_device(void);
void find_unused_port(u_short req);

size_t build_syn_packet(u_char* packet, uint32_t src, uint32_t dst, uint16_t id, 
        uint8_t ttl, uint16_t sp ,uint16_t dp);
void build_ip_packet(u_char* packet, uint16_t ip_len, uint8_t tos, uint16_t id, 
        uint16_t frag,uint8_t ttl, uint8_t prot, uint32_t src, uint32_t dst,
        const uint8_t *payload, uint32_t payload_s);
void build_tcp_packet(u_char* packet, uint16_t sp, uint16_t dp, uint32_t seq, 
        uint32_t ack, uint8_t control, uint16_t win, uint16_t urg, 
        const uint8_t *payload, uint32_t payload_s); 
void dump_packet(u_char* packet, int len);

u_short in_chksum(u_char *addr, int len);
u_short tcp_chksum(u_char *addr); 

char* find_host(char *ip_addr); 
char* ip_to_str(u_long addr); 
double time_diff(struct timeval* t1, struct timeval *t2);

