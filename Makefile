all:
	gcc -std=gnu99 -Wall -Wextra main.c packet.c probe.c capture.c utility.c -o traceroute -lpcap

clean:
	rm traceroute

