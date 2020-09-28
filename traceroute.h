/*
 * CS3103 Assignment 2 Part C
 * Name: Rahul Rajesh
 * Matric Number: A0168864L
 */

/*
 * All declarations in our traceroute implementation can be found here
 */

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
#include <ctype.h>
#include <unistd.h>
#include <math.h>

//MACROs purely for utility

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

//all user provided input
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

//record struct to store details of outgoing/incoming
//packets
struct record {
    int ttl;
    int q;
    u_short id;
    struct timeval timestamp;
    double delta_time;
    char *addr, *dnat_ip;
};

//global constants
#define MX_PKT_SZ 500
#define MX_TEXT 500
#define SYN_PK_SIZE 100
#define DEFAULT_DEST_PORT 80

extern pcap_t* pcap; //capture device
extern struct config* conf; //parameters
extern int send_sck; //socket used to send 
extern int pcap_sck; //socket used to recv

/*
 * Starts a listening device on specific interface
 * that captures raw packets straight from the wire
 * Function set's up filters so that we don't read
 * in unnecessary packets
 */
void start_pcap_listener();

/*
 * Creates and sends out an empty TCP SYN packet 
 * and stores timing/packet details in log
 */
void probe(struct record *log); 

/*
 * Attempts to capture a packet. Stores packet + metadata onto buffer
 * and pkt_hdr respectively. We only wait till timeout
 */
int capture(const u_char** buffer, struct pcap_pkthdr** pkt_hdr, int timeout);

/*
 * Checks if the packet in buffer/pkt_hdr is related to the outgoing packet
 * using log.
 * Returns
 * 0 : packet okay 
 * 1 : packet okay + des reached
 * -1 : incorrect packet
 */
int packet_ok(u_char* buffer, struct pcap_pkthdr* pkt_hdr, struct record* log);

/*
 * Packet related functions below
 * Reads in all relevant header data and packs it into a byte buffer
 */

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


/*
 * Utility Functions below to do:
 * 1. dns lookup
 * 2. reverse dns 
 * 3. interface lookup
 * 4. string conversion / time calculation
 *
 * Some of these functions store their result straight to conf obj above!
 */

void find_usable_addr(const char* node);
void find_src_addr(void);
void find_device(void);
void find_unused_port(u_short req);
char* find_host(char *ip_addr); 
char* ip_to_str(u_long addr); 
double time_diff(struct timeval* t1, struct timeval *t2);

