/*
 * CS3103 Assignment 2 Part C
 * Name: Rahul Rajesh
 * Matric Number: A0168864L
 */


// Traceroute implementation in C
// refer to README file for information on running

#include "traceroute.h"

void prep_sockets(); 
int trace();
void usage(char**);

struct config* conf;
int send_sck, rcv_sck;

const uint16_t DEFAULT_PORT = 80;

char dst_prt_name[MX_TEXT];

int main(int argc, char *argv[]) 
{
    if (argc != 2) {
        usage(argv);
        return -1;
    }

    conf = calloc(1, sizeof(struct config));
    if (conf == NULL) {
        perror("error in calloc for conf\n");
        return -1;
    }   
    
    //fill up config object
    conf->max_ttl = 15;
    conf->nqueries = 3;
    conf->dst_port = DEFAULT_PORT;
    conf->timeout = 5000;
    conf->device = NULL;

    find_usable_addr(argv[1]);
    find_src_addr();
    find_unused_port(0);

    find_device();
    if (conf->device) {
        fprintf(stderr, "Selected device %s, address %s, port %d\n", conf->device, ip_to_str(conf->src), conf->src_port);
    } else {
        fprintf(stderr, "%s\n", "unable to find device");
    }

    struct servent* serv;

    //TODO: this is a security risk (check safety before snprintf)
    if ((serv = getservbyport(htons(conf->dst_port), "tcp")) == NULL) {
        snprintf(dst_prt_name, MX_TEXT, "%d", conf->dst_port);
    } else {
        snprintf(dst_prt_name, MX_TEXT, "%d (%s)", conf->dst_port, serv->s_name);
    }

    prep_sockets();
    start_pcap_listener();
    trace();
}

void prep_sockets() {
    send_sck = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (send_sck < 1) {
        perror("error creating socket for sending");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(send_sck, IPPROTO_IP, IP_HDRINCL, &optval ,sizeof(optval)) < 0) {
        perror("cannot set socket option for sending socket");
        exit(EXIT_FAILURE);
    }

    rcv_sck = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rcv_sck < 1) {
        perror("error creating socket for rcving");
        exit(EXIT_FAILURE);
    }
}

int trace(void)
{
    fprintf(stderr, "Tracing the path to %s on TCP port %s, %d hops max\n",
            conf->dst_name, dst_prt_name, conf->max_ttl); 


    const u_char *buffer;
    struct pcap_pkthdr *pkt_hdr;
    int last_succ;
    int done = 0;

    for (int ttl = 1; ttl <= conf->max_ttl && !done; ++ttl) {
        printf("%2u ", ttl);
        last_succ = 0;

        for (int q = 1; q <= conf->nqueries; ++q) {
            struct record *log = calloc(1, sizeof(struct record));
            if (log == NULL) {
                perror("calloc record failed");
                exit(EXIT_FAILURE);
            }

            log->ttl = ttl;
            log->q = q;

            probe(log);
            //printf("Send packet with ttl %d [q: %d]\n", ttl, q);

            int read_sz = 0;
            while ((read_sz = capture(&buffer, &pkt_hdr, conf->timeout)) > 0) {
                int status = packet_ok((u_char*)buffer, pkt_hdr, log);
                if (status == -1) {
                    continue;
                }

                if (!last_succ) {
                    if (log->addr) {
                        printf("%s (%s) ", log->addr, log->dnat_ip);
                    } else {
                        printf("%s ", log->dnat_ip);
                    }
                    last_succ = 1;
                } 

                if (status) {
                    done = 1;
                }

                printf(" %g ms", log->delta_time);
                break;
            }

            //timeout
            if (read_sz == 0) {
                printf(" *");
            }

            fflush(stdout);
        }

        //completed!
        if (done) {
            printf(" (Reached)");
        }

        printf("\n");
    }

    if (!done) {
        fprintf(stderr, "Destination not reached\n");
    }

    return 0;
}

void usage(char *argv[]) 
{
    printf("usage %s [dest addr/hostname]\n", argv[0]);
}

