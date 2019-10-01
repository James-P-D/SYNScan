// Scan filter: (tcp.port==80||tcp.port==81)&&(ip.dst==192.168.100.52)
//
// TODO
//   IP:
//		Source IP
//		Dest IP
//

#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <Iphlpapi.h>
#include <winsock.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "ws2_32.lib")
//#pragma comment(lib, "winpcap.lib")

// Constants for Ethernet section of packet
#define ETHERNET_IPV4          0x0800

// Constants for IP section of packet
#define IP_VIHL                0x45
#define IP_DSCP_ECN            0x00
#define IP_LENGTH		       0x002C
#define IP_ID	               0x0000
#define IP_FLAGS_FOFFSET       0x0000
#define IP_TIME_TO_LIVE        0xFF
#define IP_TCP                 0x06

// Constants for TCP section of packets
#define TCP_SEQ_NO             0x00000000
#define TCP_ACK_NO             0x00000000
#define TCP_OFFSET             0x60
#define TCP_FLAGS              0x02  // Syn only
#define TCP_WINDOW_SIZE        0x0000
#define TCP_URGENT_PTR         0x0000
#define TCP_MAX_SEG_SIZE       0x02
#define TCP_LENGTH             0x04
#define TCP_MSS_VALUE          0x05b4

// Constants for internal use
#define DEVICE_STRING_SIZE     100
#define IP_ADDRESS_STRING_SIZE 20
#define MAX_PORTS              65536
#define PACKET_SIZE            58

// Function prototypes
void copy_u_short_to_array(u_char * array, int index, u_short val);
void copy_u_long_to_array(u_char* array, int index, u_long val);
u_short calculate_ip_checksum(u_char packet[PACKET_SIZE]);
u_short calculate_tcp_checksum(u_char packet[PACKET_SIZE]);

/*
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
*/

void usage() {
	pcap_if_t* allDevices, * device;
	char errorBuffer[PCAP_ERRBUF_SIZE];

	fprintf(stdout, "Usage: SYNSCAN.EXE Adaptor-GUID IP-Address Port1 Port2 .. PortN\n");
	fprintf(stdout, "e.g. SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 21 23 80\n");
	fprintf(stdout, "     SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 0-1024\n");
	fprintf(stdout, "     SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 0-1024 6667 1234\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "Finding available adaptors....\n");

	if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
		fprintf(stdout, "Error getting devices (pcap_findalldevs()): %s\n", errorBuffer);
		exit(1);
	}
	for (device = allDevices; device; device = device->next) {
		if (device->description) {
			fprintf(stdout, "%s\t(%s)\n", device->name, device->description);
		}
		else {
			fprintf(stdout, "%s\t(No description)\n", device->name);
		}
	}
}

int parseArgv(int argc, char* argv[], char device[], char ipAddress[], u_short ports[], int* portCount) {
	strcpy_s(device, DEVICE_STRING_SIZE, argv[1]);
	strcpy_s(ipAddress, IP_ADDRESS_STRING_SIZE, argv[2]);

	fprintf(stdout, "Adaptor:\t%s", device);
	fprintf(stdout, "IP:\t%s\n", ipAddress);

	*portCount = 0;
	for (int i = 3; i < argc; i++) {
		//char* c = argv[i];
		char* e = strchr(argv[i], '-');
		if (e == NULL) {
			int port = atoi(argv[i]);
			if ((port < 1) || (port > 65535)) {
				fprintf(stderr, "%s is not a valid port number\n", argv[i]);
				return FALSE;
			}
			ports[*portCount] = (u_short)port;
			(*portCount)++;
			if (*portCount > MAX_PORTS) {
				fprintf(stderr, "Too many ports\n");
				return FALSE;
			}
		}
		else {
			char* token2 = NULL;
			char* token1 = strtok_s(argv[i], "-", &token2);
			if (token1 != NULL && token2 != NULL) {
				int lowPort = atoi(token1);
				int highPort = atoi(token2);

				if ((lowPort < 1) || (lowPort > 65535)) {
					fprintf(stderr, "%d is not a valid port number\n", lowPort);
					return FALSE;
				}
				if ((highPort < 1) || (highPort > 65535)) {
					fprintf(stderr, "%d is not a valid port number\n", highPort);
					return FALSE;
				}
				if (lowPort >= highPort) {
					fprintf(stderr, "%s is not a valid port range\n", argv[i]);
					return FALSE;
				}

				for (int j = lowPort; j <= highPort; j++) {
					ports[*portCount] = (u_short)j;
					(*portCount)++;
					if (*portCount > MAX_PORTS) {
						fprintf(stderr, "Too many ports\n");
						return FALSE;
					}
				}
			}
			else {
				fprintf(stderr, "%s is not a valid port number\n", argv[i]);
				return FALSE;
			}
		}
	}

	fprintf(stdout, "Adaptor:\t%s", device);
	fprintf(stdout, "IP:\t%s\n", ipAddress);
	fprintf(stdout, "Ports:\t");
	for (int i = 0; i < *portCount; i++) {
		fprintf(stdout, "%d, ", ports[i]);
	}
	fprintf(stdout, "\n");
	return TRUE;
}

BOOL SetEthernetFields(u_char packet[PACKET_SIZE]) {
	/*
	Set the Ethernet section of the packet (12 bytes)
	( https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II )

	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	| 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 |
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	|     Source MAC Address      |   Destination MAC Address   |  Type   |
	+-----------------------------+-----------------------------+---------+

	First 6 bytes are source adaptor MAC address
	Next 6 bytes are destination adaptor MAC address (leave as zero)
	Next 2 bytes are type. 0x0800 for Internet Protocol ( https://en.wikipedia.org/wiki/EtherType#Examples )
	*/

	DWORD size;
	PIP_ADAPTER_ADDRESSES adapterAddresses, adapterAddress;
	PIP_ADAPTER_UNICAST_ADDRESS unicastAddress;
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
		printf("Unable to get network adaptors(GetAdaptersAddresses())");
		return FALSE;
	}
	adapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(size);

	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapterAddresses, &size) != ERROR_SUCCESS) {
		printf("Unable to get network adaptors(GetAdaptersAddresses())");
		free(adapterAddresses);
		return FALSE;
	}

	for (adapterAddress = adapterAddresses; adapterAddress != NULL; adapterAddress = adapterAddress->Next) {
		//print_adapter(aa);
		printf("%s", adapterAddress->AdapterName);
		//printf(aa->PhysicalAddressLength);
		for (unicastAddress = adapterAddress->FirstUnicastAddress; unicastAddress != NULL; unicastAddress = unicastAddress->Next) {
			//print_addr(ua);
		}
	}

	// Set source MAC address to zero
	memset(packet, 0, 6);

	// Set destination MAC address to zero
	memset(packet + 6, 0, 6);

	// EtherType 0x0800 for IPv4 https://en.wikipedia.org/wiki/EtherType#Examples
	copy_u_short_to_array(packet, 12, (u_short)ETHERNET_IPV4);

	free(adapterAddresses);

	return TRUE;
}

void SetInternetProtocolFields(u_char packet[PACKET_SIZE]) {
	/*
	Set the Internet Protocol section of the packet
	( https://en.wikipedia.org/wiki/IPv4#Header )

	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	| 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 |
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	|                                                                     |VIHL| DE |
	+---------+---------+---------+----+----+---------+-------------------+----+----+
	| Length  |   ID    |  F&FO   |TTL |PRTL| HCHCKSM |     Source IP     | Dest... |
	+---------+---------+---------+----+----+---------+-------------------+---------+
	| ...IP   |
	+---------+
	*/

	// Version and IHL
	packet[14] = IP_VIHL;

	// DSCP and ECN
	packet[15] = IP_DSCP_ECN;

	// Total Length
	copy_u_short_to_array(packet, 16, IP_LENGTH);

	// ID
	copy_u_short_to_array(packet, 18, IP_ID);

	// Flags and Fragment Offset
	copy_u_short_to_array(packet, 20, IP_FLAGS_FOFFSET);

	// Time to Live
	packet[22] = IP_TIME_TO_LIVE;

	// Protocol
	packet[23] = IP_TCP;

	// Header Checksum
	u_short ip_checksum = calculate_ip_checksum(packet);
	copy_u_short_to_array(packet, 24, ip_checksum);

	// Source IP
	//TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	// Destination IP
	//TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
}

void SetTCPFields(u_char packet[PACKET_SIZE], u_short dest_port) {
	/*
	Set the TCP section of the packet
	(https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)

	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	| 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 |
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	|                                                                               |
	+-------------------------------------------------------------------------------+
	|                                                                               |
	+---------+---------+---------+-------------------+-------------------+----+----+
	|         |	SrcPort | DstPort |  Sequence Number  |    Ack Number     |OFST|FLGS|
	+---------+---------+---------+----+----+---------+-------------------+----+----+
	|  WSize  | ChkSum  | UrgtPtr | K  | L  | DegSize |
	+---------+---------+---------+----+----+---------+
	*/

	//packet[34] = SrcPort;
	//TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	//packet[36] = destPort;
	copy_u_short_to_array(packet, 36, dest_port);

	// Sequence No.
	copy_u_long_to_array(packet, 38, TCP_SEQ_NO);

	// Ack No.
	copy_u_long_to_array(packet, 42, TCP_ACK_NO);

	// Offset
	packet[46] = TCP_OFFSET;

	// Flags
	packet[47] = TCP_FLAGS;

	// Window Size
	copy_u_short_to_array(packet, 48, TCP_WINDOW_SIZE);

	//packet[50] = Checksum;
	u_short tcp_checksum = calculate_ip_checksum(packet);
	copy_u_short_to_array(packet, 50, tcp_checksum);

	// Urgent Pointer
	copy_u_short_to_array(packet, 52, TCP_URGENT_PTR);

	// Max Segment Size
	packet[54] = TCP_MAX_SEG_SIZE;

	// Length
	packet[55] = TCP_LENGTH;

	// MSS Value
	copy_u_short_to_array(packet, 56, TCP_MSS_VALUE);
}

void copy_u_short_to_array(u_char* array, int index, u_short val) {
	u_short val2 = htons(val);
	memcpy((array + index), (unsigned char*)& val2, sizeof(u_short));
}

void copy_u_long_to_array(u_char* array, int index, u_long val) {
	u_long val2 = htonl(val);
	memcpy((array + index), (unsigned char*)& val2, sizeof(u_long));
}

u_short calculate_ip_checksum(u_char packet[PACKET_SIZE]) {
	/*
	 * Calculate the IP Checksum value
	 * https://en.wikipedia.org/wiki/IPv4_header_checksum
	 */

	u_short checksum = 0;
	u_long total = 0xffff;

	// For the first 5 words, starting at offset 14, sum the words
	for (int i = 0; i < 5; i++) {
		int index = 14 + (i * 2);
		u_short word;
		memcpy(&word, packet + index, 2);
		total += ntohs(word);
	}

	// For the next 4 words, starting at offset 26 (so we skip the
	// checksum word in the IP header), sum the words
	for (int i = 0; i < 4; i++) {
		int index = 26 + (i * 2);
		u_short word;
		memcpy(&word, packet + index, 2);
		total += ntohs(word);
	}

	// Whilst the sum is too large to fit in a word, grab the carries
	// and add to the total
	while (total > 0xFFFF) {
		u_short carry = total >> 16;
		total += carry;
	}

	// Finally, calculate onescomplement (not) and return in correct endian-ness
	return htons(~checksum);
}

u_short calculate_tcp_checksum(u_char packet[PACKET_SIZE]) {
	u_short checksum = 0;
	u_long total = 0xffff;

	// For the first 8 words, starting at offset 34, sum the words
	for (int i = 0; i < 8; i++) {
		int index = 34 + (i * 2);
		u_short word;
		memcpy(&word, packet + index, 2);
		total += ntohs(word);
	}

	// For the next 2 words, starting at offset 52 (so we skip the
	// checksum word in the TCP header), sum the words
	for (int i = 0; i < 2; i++) {
		int index = 52 + (i * 2);
		u_short word;
		memcpy(&word, packet + index, 2);
		total += ntohs(word);
	}

	// Whilst the sum is too large to fit in a word, grab the carries
	// and add to the total
	while (total > 0xFFFF) {
		u_short carry = total >> 16;
		total += carry;
	}

	// Finally, calculate onescomplement (not) and return in correct endian-ness
	return htons(~checksum);
}

int main(int argc, char** argv) {
	pcap_t* fp;
	char errorBuffer[PCAP_ERRBUF_SIZE];
	u_char packet[PACKET_SIZE];

	//print_ipaddress();
	//usage();

	if (argc < 3) {
		usage();
		return 1;
	}

	char device[DEVICE_STRING_SIZE];
	char ipAddress[IP_ADDRESS_STRING_SIZE];
	u_short ports[MAX_PORTS];
	int portCount = 0;
	if (!parseArgv(argc, argv, &device, &ipAddress, &ports, &portCount)) {
		return 2;
	}

	/*******************************************************************************************/

	/* Open the network adapter */
	if ((fp = pcap_open_live(device, 65536, 1, 1000, errorBuffer)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter %s\n", device);
		return 2;
	}

	for (int j = 0; j < portCount; j++) {
		SetEthernetFields(packet);
		SetInternetProtocolFields(packet, ipAddress);
		SetTCPFields(packet, ports[j]);

		if (pcap_sendpacket(fp, packet, PACKET_SIZE) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
			return 3;
		}
	}

	pcap_close(fp);
	return 0;
}