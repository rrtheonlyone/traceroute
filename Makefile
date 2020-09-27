all:
	gcc -std=c99 -Wall -Wextra main.c packet.c probe.c capture.c -o traceroute -lpcap

clean:
	rm traceroute

