/*
 * CS3103 Assignment 2 Part C
 * Name: Rahul Rajesh
 * Matric Number: A0168864L
 */


// Traceroute implementation in C
// refer to README file for information on running

/* 
 * The main program that helps us to read in the arguments and 
 * kickstart the tracing program. The main file helps to also
 * print the write messages to the correct output streams. 
 *
 * Logic within the file has been abstracted into other files
 * to make this more readable:
 * - packet.c:
 * - probe.c:
 * - util.c:
 * - capture.c:
 *
 * The traceroute.h header file provides struct or vairable declarations
 * we use in our application
 */

#include "traceroute.h"

int get_optarg(); 
void prep_sockets(); 
int trace();
void usage(char**);

//see header file for these
struct config* conf;
int send_sck;

//strings for printing later
char *optstr;
char dst_prt_name[MX_TEXT];

int main(int argc, char *argv[]) 
{
    //lets create a conf object to fill up the struct
    conf = calloc(1, sizeof(struct config));
    if (conf == NULL) {
        perror("error in calloc for conf\n");
        exit(EXIT_FAILURE);
    }   
   
    //defaults
    conf->max_ttl = 15;
    conf->nqueries = 3;
    conf->dst_port = DEFAULT_DEST_PORT;
    conf->timeout = 5000;
    conf->device = NULL;

    //read in user defined flag
    int c;
    optstr = "hm:w:q:";
    while ((c = getopt(argc, argv, optstr)) != -1) {
        switch (c) {
            case 'm':
                conf->max_ttl = max(1, get_optarg());
                break;
            case 'w':
                conf->timeout = max(1000, get_optarg());
                break;
            case 'q':
                conf->nqueries = max(1, get_optarg());
                break;
            case 'h':
                usage(argv);
                break; //unnecessary but to silence compiler warning
            case '?':
            default:
                if (optopt != ':' && strchr(optstr, optopt)) {
					fprintf(stderr, "Argument required for -%c\n", optopt);
                    exit(EXIT_FAILURE);
                }
				fprintf(stderr, "Unknown command line argument: -%c\n", optopt);
                usage(argv);
        }
    }

    argc -= optind;
    argv += optind;
    if (argc > 1 && check_numeric(argv[1])) {
        conf->dst_port = atoi(argv[1]);
    }

    //dns + interface lookup before we send
    find_usable_addr(argv[0]);
    find_src_addr();
    find_unused_port(0);
    find_device();
    if (conf->device) {
        fprintf(stderr, "Selected device %s, address %s, port %d\n", 
                conf->device, ip_to_str(conf->src), conf->src_port);
    } else {
        fprintf(stderr, "%s\n", "unable to find device");
    }
    
    //reverse DNS look up 
    struct servent* serv;
    if ((serv = getservbyport(htons(conf->dst_port), "tcp")) == NULL) {
        snprintf(dst_prt_name, MX_TEXT, "%d", conf->dst_port);
    } else {
        snprintf(dst_prt_name, MX_TEXT, "%d (%s)", conf->dst_port, serv->s_name);
    }

    prep_sockets();
    start_pcap_listener();
    trace();
}

//prepares necessary sockets that we will be using
void prep_sockets() {
    send_sck = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (send_sck < 1) {
        perror("error creating socket for sending");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(send_sck, IPPROTO_IP, IP_HDRINCL, &optval ,
                sizeof(optval)) < 0) {
        perror("cannot set socket option for sending socket");
        exit(EXIT_FAILURE);
    }
}

//start sending out packets!
int trace(void)
{
    fprintf(stderr, "Tracing the path to %s (%s) on TCP port %s, %d hops max\n",
            conf->dst_name, inet_ntoa(((struct sockaddr_in*)conf->dst)->sin_addr)
            , dst_prt_name, conf->max_ttl); 

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
            
#ifdef DEBUG
            printf("Send packet with ttl %d [q: %d]\n", ttl, q);
#endif

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

//help message to inform users of our params
void usage(char *argv[]) 
{
    //printf("\nusage %s <host> [destination port]\n", argv[0]);
    printf("Usage: %s [-q <number of queries>] [-m <max ttl>]\n\
            [-w <wait time (ms)>] <host> [destination port]\n\n", argv[0]);    
    exit(EXIT_SUCCESS);
}

//checks if command line flags are numbers
int get_optarg() 
{
    int is_number = check_numeric(optarg);
    if (!is_number) {
        fprintf(stderr, "Numeric argument required for -%c\n", optopt);
        exit(EXIT_FAILURE);
    }

    return atoi(optarg);
}

