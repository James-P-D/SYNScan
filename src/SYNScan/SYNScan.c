// TODO: Check we need all these #includes
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <objbase.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
// TODO: Add pcap library locally for check-in
#define HAVE_REMOTE
#include <pcap.h>

// Winsock has limited RAW packet support, so must use npcap ( https://www.binarytides.com/raw-sockets-packets-with-winpcap/ )

// Link with ws2_32.lib and ole32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "ole32.lib")

#define IP_ADDRESS_STRING_SIZE (20)
#define MAX_PORTS (65536)
//#define TRUE (1)
//#define FALSE (0)

void usage() {
	printf("Usage: SCAN.EXE IP-Address Port1 Port2 .. PortN\n");
	printf("e.g. SCAN.EXE 127.0.0.1 21 23 80\n");
	printf("     SCAN.EXE 127.0.0.1 0-1024\n");
	printf("     SCAN.EXE 127.0.0.1 0-1024 6667 1234\n");
}

int parseArgv(int argc, char* argv[], char ipAddress[], int ports[], int* portCount) {
	strcpy_s(ipAddress, IP_ADDRESS_STRING_SIZE, argv[1]);
	printf("Ip: %s\n", ipAddress);

	*portCount = 0;
	for (int i = 2; i < argc; i++) {
		char* c = argv[i];
		char* e = strchr(argv[i], '-');
		if (e == NULL) {
			int port = atoi(argv[i]);
			if ((port < 1) || (port > 65535)) {
				printf("%s is not a valid port number\n", argv[i]);
				return FALSE;
			}
			ports[*portCount] = port;
			(*portCount)++;
			if (*portCount > MAX_PORTS) {
				printf("Too many ports\n");
				return FALSE;
			}
		}
		else {
			char* token2;
			char* token1 = strtok_s(argv[i], "-", &token2);
			int lowPort = atoi(token1);
			int highPort = atoi(token2);

			if ((lowPort < 1) || (lowPort > 65535)) {
				printf("%s is not a valid port number\n", lowPort);
				return FALSE;
			}
			if ((highPort < 1) || (highPort > 65535)) {
				printf("%s is not a valid port number\n", highPort);
				return FALSE;
			}
			if (lowPort >= highPort) {
				printf("%s is not a valid port range\n", argv[i]);
				return FALSE;
			}

			for (int j = lowPort; j <= highPort; j++) {
				ports[*portCount] = j;
				(*portCount)++;
				if (*portCount > MAX_PORTS) {
					printf("Too many ports\n");
					return FALSE;
				}
			}
		}
	}
	return TRUE;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return 1;
	}

	char ipAddress[IP_ADDRESS_STRING_SIZE];
	int ports[MAX_PORTS];
	int portCount = 0;
	if (!parseArgv(argc, argv, &ipAddress, &ports, &portCount)) {
		return 2;
	}

	DWORD error;
	WSADATA data;
	WORD version = MAKEWORD(2, 2);

	if (WSAStartup(version, &data)) {
		error = WSAGetLastError();
		printf("Unable to initialise (WSAStartup()) - Error %d\n", error);
		return 3;
	}

	struct addrinfo* result;
	if (getaddrinfo(ipAddress, NULL, NULL, &result) != 0) {
		return 4;
	}

	char _address[INET6_ADDRSTRLEN];
	for (struct addrinfo* _res = result; _res != NULL; _res = _res->ai_next) {
		if (_res->ai_family == AF_INET) {
			if (NULL == inet_ntop(AF_INET, &((struct sockaddr_in*)_res->ai_addr)->sin_addr, _address, sizeof(_address))) {
				perror("inet_ntop");
				return EXIT_FAILURE;
			}

			printf("%s\n", _address);
		}
	}



	pcap_if_t* alldevs;
	//pcap_rmtau	
	//pcap_rmtauth auth; &auth
	char errbuf[PCAP_ERRBUF_SIZE];
	//pcap_findalldevs_ex
	//if (pcap_findalldevs(PCAP_SRC_IF_STRING, &errbuf)) {
	//}

	/*
	if (pcap_findalldevs(PCAP_SRC_IF_STRING, NULL, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	*/

	pcap_if_t* d;
	int i = 0;
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	//pcap_open()
	WSACleanup();
	return 0;
}