/*
 * CS3103 Assignment 2 Part C
 * Name: Rahul Rajesh
 * Matric Number: A0168864L
 */

/*
 * This library deals directly with pcap listener 
 * It helps open a connection onto a specific device
 * Much of the logic is heavily inspired by:
 * https://github.com/mct/tcptraceroute/blob/master/capture.c
 */

#include "traceroute.h"

//refer to header files
pcap_t *pcap;
int pcap_sck;

//global strings for printing
char errbuf[MX_TEXT];
char filter[MX_TEXT];

//opens listener to start capturing and updates global const
void start_pcap_listener()
{
    pcap = pcap_open_live(conf->device, MX_PKT_SZ, 0, 10, errbuf);
    if (!pcap) {
        perror("error opening pcap");
        exit(EXIT_FAILURE);
    } 

    bpf_u_int32 localnet = 0;
    bpf_u_int32 netmask = 0;
    if (pcap_lookupnet(conf->device, &localnet, &netmask, errbuf) < 0) {
        fprintf(stderr, "pcap_lookupnet failed: %s\n", errbuf);
    }

    uint32_t d_addr = ((struct sockaddr_in*) conf->dst)->sin_addr.s_addr;
    char* dst_ip = ip_to_str(d_addr);
    char* src_ip = ip_to_str(conf->src);

	snprintf(filter, MX_TEXT, "\n\
		(tcp and src host %s and src port %d and dst host %s)\n\
		or ((icmp[0] == 11 or icmp[0] == 3) and dst host %s)",
			    dst_ip, conf->dst_port, src_ip, src_ip);

    struct bpf_program fcode;
    if (pcap_compile(pcap, &fcode, filter, 1, netmask) < 0) {
        perror("error compiling filter");
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(pcap, &fcode) < 0) {
        perror("error setting filter");
        exit(EXIT_FAILURE);
    }

    pcap_sck = pcap_fileno(pcap);
}

