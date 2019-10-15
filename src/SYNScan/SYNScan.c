// TODO
// 1) Destination MAC Address
// 2) IP Address formats
// 3) Receiving Packets
//https://stackoverflow.com/questions/3281278/what-should-the-destination-mac-address-be-set-to-when-sending-packet-outside-of
//https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp?redirectedfrom=MSDN
//https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp
//https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp?redirectedfrom=MSDN
//#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <winsock.h>
#include <Iphlpapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")

// Constants for Ethernet section of packet
#define ETHERNET_IPV4          0x0800

// Constants for IP section of packet
#define IP_VIHL                0x45
#define IP_DSCP_ECN            0x00
#define IP_LENGTH		       0x002C
#define IP_ID	               0x568E
#define IP_FLAGS_FOFFSET       0x0000
#define IP_TIME_TO_LIVE        0x32
#define IP_TCP                 0x06
#define IP_INITIAL_CHECKSUM    0x0000

// Constants for TCP section of packets
#define TCP_SEQ_NO             0x00000000
#define TCP_ACK_NO             0x00000000
#define TCP_OFFSET             0x60
#define TCP_FLAGS_SYN          0x02  // Syn only
#define TCP_FLAGS_RST          0x04  // Reset only
#define TCP_FLAGS_ACK          0x10  // Ack only
#define TCP_WINDOW_SIZE        0x0400
#define TCP_URGENT_PTR         0x0000
#define TCP_MAX_SEG_SIZE       0x02
#define TCP_LENGTH             0x04
#define TCP_MSS_VALUE          0x05b4
#define TCP_INITIAL_CHECKSUM   0x0000

// Constants for internal use
#define DEVICE_STRING_SIZE     100
#define MAX_PORTS              65536
#define PACKET_SIZE            58
#define MAC_ADAPTER_LENGTH     6
#define IP_ADDRESS_LENGTH      4
#define PSEUDO_HEADER_SIZE     12

//TODO Move this
#ifdef WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

// Function prototypes
void usage();
int parse_argv(int argc, char* argv[], char device[], char ipAddress[], u_short ports[], int* portCount);
BOOL get_source_adaptor_details(char device[], u_char mac_address[], u_char ip_address[]);
BOOL get_source_adaptor_full_name(char device[], char device_full_name[]);
//BOOL get_destination_adaptor_details();
BOOL string_to_ipaddress(char* str, u_char ip_address[]);
void copy_u_short_to_array(u_char* array, int index, u_short val);
void copy_u_long_to_array(u_char* array, int index, u_long val);
u_short calculate_ip_checksum(u_char packet[PACKET_SIZE]);
u_short calculate_tcp_checksum(u_char packet[PACKET_SIZE]);
void set_ethernet_fields(u_char packet[PACKET_SIZE], u_char mac_address[MAC_ADAPTER_LENGTH]);
void set_internet_protocol_fields(u_char packet[PACKET_SIZE]);
void set_tcp_fields(u_char packet[PACKET_SIZE], u_short dest_port);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

int main(int argc, char** argv) {
	pcap_t* fp;
	char errorBuffer[PCAP_ERRBUF_SIZE];
	u_char packet[PACKET_SIZE];

#ifdef WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif

	if (argc < 3) {
		usage();
		return 1;
	}

	char device[DEVICE_STRING_SIZE];
	char dest_ip_address[INET_ADDRSTRLEN];
	u_short ports[MAX_PORTS];
	int portCount = 0;
	if (!parse_argv(argc, argv, &device, &dest_ip_address, &ports, &portCount)) {
		return 2;
	}

	u_char source_mac_address[MAC_ADAPTER_LENGTH];
	u_char source_ip_address[IP_ADDRESS_LENGTH];
	if (!get_source_adaptor_details(device, source_mac_address, source_ip_address)) {
		return 3;
	}

	u_char dest_mac_address[MAC_ADAPTER_LENGTH];
	//if(!get_destination_adaptor_details()){
	//  return 4;
    //}

	char device_name[200];
	if (!get_source_adaptor_full_name(device, device_name)) {
		return 4;
	}
	
	// Open the network adapter	
	if ((fp = pcap_open_live(device_name, 65536, 1, 1000, errorBuffer)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter %s\n", device);
		return 4;
	}
	
	// Start receiving packets *before* we start sending them, otherwise we
	// might miss responses
	pcap_loop(fp, 0, packet_handler, NULL);

	// Build the packets and send
	for (int j = 0; j < portCount; j++) {
		set_ethernet_fields(packet, source_mac_address, dest_mac_address);
		set_internet_protocol_fields(packet, source_ip_address, dest_ip_address);
		set_tcp_fields(packet, ports[j]);
				
		if (pcap_sendpacket(fp, packet, PACKET_SIZE) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
			return 3;
		}
		else {
			fprintf(stdout, "Port %d\n", ports[j]);
		}
	}

	pcap_close(fp);

	return 0;
}

void usage() {
	pcap_if_t *allDevices, *device;
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

BOOL parse_argv(int argc, char* argv[], char device[], char ipAddress[], u_short ports[], int* portCount) {
	strcpy_s(device, DEVICE_STRING_SIZE, argv[1]);
	strcpy_s(ipAddress, INET_ADDRSTRLEN, argv[2]);

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

	return TRUE;
}

BOOL get_source_adaptor_details(char device[], u_char mac_address[], u_char ip_address[]) {
	BOOL found_adaptor = FALSE;

	//MOVE THIS TO get_device_Details since GetAdaptorInfo is deprecated!!!
	
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
		if (!strcmp(adapterAddress->AdapterName, device)) {
			found_adaptor = TRUE;
			memcpy(mac_address, adapterAddress->PhysicalAddress, adapterAddress->PhysicalAddressLength);

			ip_address = "";
		}		
	}

	if (!found_adaptor) {
		fprintf(stderr, "Unable to find adaptor\n");
		return FALSE;
	}
	return TRUE;
}

BOOL get_source_adaptor_full_name(char device[], char device_full_name[]) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return FALSE;
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		if (strstr(d->name, device) != NULL) {
			strcpy_s(device_full_name, 200, d->name);
			pcap_freealldevs(alldevs);
			return TRUE;
		}
	}

	pcap_freealldevs(alldevs);
	return FALSE;
}

/*
BOOL get_destination_adaptor_details() {
	int intAddress = (int)BitConverter.ToUInt32(dst.GetAddressBytes(), 0);
	byte[] macAddr = new byte[6];
	int macAddrLen = macAddr.Length;
	int retValue = SendArp(intAddress, 0, macAddr, ref macAddrLen);
	if (retValue != 0)
	{
		return FALSE;
	}

	return TRUE;
}
*/

BOOL string_to_ipaddress(char* str, u_char ip_address[]) {
	struct sockaddr_in sa;
	
	return inet_pton(AF_INET, str, &(sa.sin_addr));
}

void copy_u_short_to_array(u_char *array, int index, u_short val) {
	u_short val2 = htons(val);
	memcpy((array + index), (unsigned char*)&val2, sizeof(u_short));
}

void copy_u_long_to_array(u_char *array, int index, u_long val) {
	u_long val2 = htonl(val);
	memcpy((array + index), (unsigned char*)&val2, sizeof(u_long));
}

u_short calculate_ip_checksum(u_char packet[PACKET_SIZE]) {
	/*
	* Calculate the IP Checksum value
	* https://en.wikipedia.org/wiki/IPv4_header_checksum
	*/

	u_short checksum = 0;
	u_long total = 0x00000000;

	// For the 10 words, starting at offset 14, sum the words
	for (int i = 0; i < 10; i++) {
		int index = 14 + (i * 2);
		u_short word;
		memcpy(&word, packet + index, 2);
		total += ntohs(word);
	}

	// Whilst the sum is too large to fit in a word, grab the carries
	// and add to the total
	while (total > 0xFFFF) {
		u_short carry = total >> 16;
		total = total & 0xFFFF;
		total += carry;
	}

	checksum = (u_short)total;
	// Finally, calculate onescomplement (not) and return in correct endian-ness
	return (~checksum);
}

u_short calculate_tcp_checksum(u_char packet[PACKET_SIZE]) {
	u_char pseudo_header[PSEUDO_HEADER_SIZE];
	memcpy(pseudo_header + 0, packet + 26, 4);
	memcpy(pseudo_header + 4, packet + 30, 4);
	pseudo_header[8] = 0x00;
	pseudo_header[9] = packet[23]; //( IP_TCP )
	pseudo_header[10] = 0x00;
	pseudo_header[11] = 0x18;

	u_short checksum = 0;
	u_long total = 0x00000000;

	for (int i = 0; i < 6; i++) {
		int index = i * 2;
		u_short word;
		memcpy(&word, pseudo_header + index, 2);
		total += ntohs(word);
	}

	// For the 12 words, starting at offset 34, sum the words
	for (int i = 0; i < 12; i++) {
		int index = 34 + (i * 2);
		u_short word;
		memcpy(&word, packet + index, 2);
		total += ntohs(word);
	}

	// Whilst the sum is too large to fit in a word, grab the carries
	// and add to the total
	while (total > 0xFFFF) {
		u_short carry = total >> 16;
		total = total & 0xFFFF;
		total += carry;
	}

	checksum = (u_short)total;
	// Finally, calculate onescomplement (not) and return in correct endian-ness
	return (~checksum);
}

void set_ethernet_fields(u_char packet[PACKET_SIZE], u_char mac_address[MAC_ADAPTER_LENGTH]) {
	/*
	Set the Ethernet section of the packet (12 bytes)
	( https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II )

	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	| 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 |
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	|   Destination MAC Address   |     Source MAC Address      |  Type   |
	+-----------------------------+-----------------------------+---------+
	*/
	// Set destination MAC address to zero
	memset(packet, 0, 6);
	/*
	packet[0] = 0x00;
	packet[1] = 0x1F;
	packet[2] = 0xF8;
	packet[3] = 0x00;
	packet[4] = 0x5C;
	packet[5] = 0x66;
	*/

	// Set source MAC address to zero
	memcpy(packet + 6, mac_address, MAC_ADAPTER_LENGTH);

	// EtherType 0x0800 for IPv4 https://en.wikipedia.org/wiki/EtherType#Examples
	copy_u_short_to_array(packet, 12, (u_short)ETHERNET_IPV4);

	//free(adapterAddresses);
}

void set_internet_protocol_fields(u_char packet[PACKET_SIZE]) {
	/*
	Set the Internet Protocol section of the packet
	( https://en.wikipedia.org/wiki/IPv4#Header )

	                                                                      +----+----+
																		  | 14 | 15 |
																		  +----+----+
																		  |VIHL| DE |
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	| 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 30 | 31 |
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	| Length  |   ID    |  F&FO   |TTL |PRTL| HCHCKSM |     Source IP     | Dest... |
	+----+----+---------+---------+----+----+---------+-------------------+---------+
	| 32 | 33 |
	+----+----+
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

	// Header Checksum. Initially set to zero, we will calculate it properly later.
	copy_u_short_to_array(packet, 24, IP_INITIAL_CHECKSUM);

	// Source IP
	packet[26] = 1;
	packet[27] = 2;
	packet[28] = 3;
	packet[29] = 4;

	// Destination IP
	packet[30] = 5;
	packet[31] = 6;
	packet[32] = 7;
	packet[33] = 8;

	// Header Checksum
	u_short ip_checksum = calculate_ip_checksum(packet);
	copy_u_short_to_array(packet, 24, ip_checksum);
}

void set_tcp_fields(u_char packet[PACKET_SIZE], u_short dest_port) {
	/*
	Set the TCP section of the packet
	(https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)

	          +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	          | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 |
	          +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	          |	SrcPort | DstPort |  Sequence Number  |    Ack Number     |OFST|FLGS|
	+----+----+----+----+----+----+----+----+----+----+-------------------+----+----+
	| 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 |
	+----+----+----+----+----+----+----+----+----+----+
	|  WSize  | ChkSum  | UrgtPtr | K  | L  | DegSize |
	+---------+---------+---------+----+----+---------+
	*/

	//packet[34] = SrcPort;
	copy_u_short_to_array(packet, 34, 0xD55E);

	//packet[36] = destPort;
	copy_u_short_to_array(packet, 36, dest_port);

	// Sequence No.
	copy_u_long_to_array(packet, 38, TCP_SEQ_NO);

	// Ack No.
	copy_u_long_to_array(packet, 42, TCP_ACK_NO);

	// Offset
	packet[46] = TCP_OFFSET;

	// Flags
	packet[47] = TCP_FLAGS_SYN;

	// Window Size
	copy_u_short_to_array(packet, 48, TCP_WINDOW_SIZE);

	// Set the checksum to zero for now. We calculate the actual value later.
	copy_u_short_to_array(packet, 50, TCP_INITIAL_CHECKSUM);

	// Urgent Pointer
	copy_u_short_to_array(packet, 52, TCP_URGENT_PTR);

	// Max Segment Size
	packet[54] = TCP_MAX_SEG_SIZE;

	// Length
	packet[55] = TCP_LENGTH;

	// MSS Value
	copy_u_short_to_array(packet, 56, TCP_MSS_VALUE);

	// Calculate the actual checksum
	u_short tcp_checksum = calculate_tcp_checksum(packet);
	copy_u_short_to_array(packet, 50, tcp_checksum);
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if (header->len > 1234) {
		//IP
		//  12-13 0x0800 (IP)
		//  14    0x45 (IPv4)
		//  23    0x06 (TCP)
		//  26-29 Source IP (
		//  30-33 Dest IP
		//TCP
		//  34-35 Source Port (80)
		//  36-37 Dest Port
		//  46-47 Flags
	}

	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	* unused parameters
	*/
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime = localtime(&local_tv_sec);
	//strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	printf("%d bytes\n", header->len);
}