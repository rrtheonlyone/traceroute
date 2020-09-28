# Traceroute

This is a traceroute implementation in C that sends many TCP SYN packets with increasing TTL values to the destination and prints routing path. Code has been modularised and written across many files to improve readability and make it more scalable in future.

```bash=
> sudo ./traceroute www.comp.nus.edu.sg
Selected device eth0, address 172.31.24.83, port 44949
Tracing the path to www.comp.nus.edu.sg (45.60.35.225) on TCP port 80 (http), 15 hops max
 1  * * *
 2  * * *
 3  * * *
 4  * * *
 5  * * *
 6 100.65.10.97  0.855 ms 0.453 ms 0.276 ms
 7 203.83.223.197  2.47 ms 2.551 ms 6.309 ms
 8 52.93.8.114  1.67 ms 2.536 ms 1.088 ms
 9 52.93.8.103  0.749 ms 2.795 ms 1.472 ms
10 19551.sgw.equinix.com (27.111.229.74)  1.041 ms 0.997 ms 0.969 ms
11 45.60.35.225  0.989 ms 0.928 ms 1.021 ms (Reached)
```

**Disclaimer**: Much of the code logic has been inspired by [tcptraceroute](https://github.com/mct/tcptraceroute/), [traceroute](https://github.com/openbsd/src/tree/master/usr.sbin/traceroute) and [libnet](https://github.com/libnet/libnet). We have chosen not to reinvent the wheel and take some of the good practices from these code bases (rewritten to fit our design pattern.)

## System Requirements

**Important**: The code has only been tested on a `Ubuntu 18.04 Server` and a `Mac OSX` machine. It is not guarenteed to work on a little endian machine or when IPv6 comes into play. Use with caution.

In order to get the code working `libpcap-dev` library has to be present. It is usually present by default but if not download it. A working version of `gcc`, `make` is also needed to compile and run the code. 

### Setup for Linux

```bash=
sudo apt install libpcap-dev
sudo apt install gcc
sudo apt install make
```

## Running the program

A `Makefile` has been provided for convenience. To run the program simply run `make` followed by `./traceroute`. Note that since we are using raw sockets, sudo or root access will be required to run this program.

## Command Line Arguments

You are free to adjust the timeout limit, the number of queries for a single packet and the total hops through command line flags. If not, default arguments will be used. You can also 

You can adjust some of the parameters for the program:
```bash=
> ./traceroute -h
Usage: ./traceroute [-q <number of queries>] [-m <max ttl>]
            [-w <wait time (ms)>] <host> [destination port]
```

You can choose to adjust certain parameters if the default value is not preferred. Here is the same command as above with adjusted parameters:

```bash=
> sudo ./traceroute -w 1000 -m 10 -q 2 www.comp.nus.edu.sg 32544
Selected device eth0, address 172.31.24.83, port 41989
Tracing the path to www.comp.nus.edu.sg (45.60.35.225) on TCP port 32544, 10 hops max
 1  * *
 2  * *
 3  * *
 4  * *
 5  * *
 6  * *
 7 100.65.9.225  0.392 ms 0.489 ms
 8 203.83.223.197  1.016 ms 1.061 ms
 9 52.93.8.26  2.712 ms 1.199 ms
10 52.93.8.17  0.77 ms 0.773 ms
Destination not reached
```

Notice we adjusted the maximum hops/number of queries/wait time through flags. We also changed default destination port to 32544 instead of 80.


## Implementation/Design 

The code logic is very similar to how `tcptraceroute` program works. We send out `TCP SYN` packets in succession with increasing `TTL` values till we hit the destination or reach max hop limit (`TTL` starts from 1). For each `TTL`, we send out `num_queries` packets (adjustable through parameter, defaults to 3)

For every packet we send, we store information about the packet in a record:

```cpp=
struct record {
    int ttl;
    int q;
    u_short id;
    struct timeval timestamp;
    double delta_time;
    char *addr, *dnat_ip;
};
```

Using the above information we are able to identify whether the incoming `ICMP` or `TCP SYN ACK` packets are related to the packets we send out. This is encompassed in the `packet_ok(..)` method found in line 64 of `packet.c`.

We check the attached ICMP payload and compare against record. We also do necessary checks on the IP addresses of the packet in the `ICMP` packet.

In order to determine whether destination has reached, the same method will return a status code if we see a `DESTINATION UNREACHABLE` or `TCP SYN ACK` packet.

For capturing packets, we use `pcap` library to get the raw packet off the wire. This is to prevent the kernel from intercepting packets that we need to read.

## Suggestions

Feel free to contribute or make suggestions to this code.

