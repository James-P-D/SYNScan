#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <ws2def.h>
#include <iphlpapi.h>
#include <tchar.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")

// Error codes
#define SUCCESS_ERROR_CODE                  0
#define CANNOT_LOAD_NPCAP_ERROR_CODE        1
#define INSUFFICIENT_ARGS_ERROR_CODE        2
#define INVALID_ARGS_ERROR_CODE             3
#define SOURCE_ADAPTOR_ERROR_CODE           4
#define DEST_ADAPTOR_ERROR_CODE             5
#define SOURCE_ADAPTOR_FULL_NAME_ERROR_CODE 6
#define OPEN_ADAPTOR_ERROR_CODE             7
#define SEND_PACKET_ERROR_CODE              8

// Constants for Ethernet section of packet
#define ETHERNET_IPV4          0x0800

// Constants for IP section of packet
#define IP_VIHL                0x45
#define IP_DSCP_ECN            0x00
#define IP_LENGTH              0x002C
#define IP_ID                  0x568E // Check this, can it not be zero?
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
#define TCP_MSS_VALUE          0x05B4
#define TCP_INITIAL_CHECKSUM   0x0000

// Constants for internal use
#define DEVICE_STRING_SIZE       100
#define MAX_PORTS                65536
#define PACKET_SIZE              58
#define MAC_ADAPTER_LENGTH       6
#define IP_ADDRESS_LENGTH        4
#define IP_ADDRESS_STRING_LENGTH 16
#define PSEUDO_HEADER_SIZE       12

// Function prototypes
BOOL LoadNpcapDlls();
void usage();
int parse_argv(int argc, char* argv[], char* device, char ipAddress[], u_short ports[], int* portCount);
BOOL get_source_adaptor_details(char device[], u_char mac_address[], u_char ip_address[]);
BOOL get_source_adaptor_full_name(char device[], char device_full_name[]);
BOOL string_to_ipaddress(char* str, u_char ip_address[]);
void copy_u_short_to_array(u_char* array, int index, u_short val);
void copy_u_long_to_array(u_char* array, int index, u_long val);
u_short calculate_ip_checksum(u_char packet[PACKET_SIZE]);
u_short calculate_tcp_checksum(u_char packet[PACKET_SIZE]);
void set_ethernet_fields(u_char packet[PACKET_SIZE], u_char source_mac_address[MAC_ADAPTER_LENGTH], u_char dest_mac_address[MAC_ADAPTER_LENGTH]);
void set_internet_protocol_fields(u_char packet[PACKET_SIZE]);
void set_tcp_fields(u_char packet[PACKET_SIZE], u_short dest_port);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
BOOL get_destination_adaptor_details(char* srcIP, char* destIP, u_char dest_mac_address[MAC_ADAPTER_LENGTH]);

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

// Global Variables
pcap_t* fp;
u_char source_ip_address[IP_ADDRESS_LENGTH];
u_char dest_ip_address[IP_ADDRESS_LENGTH];
int total_ports = 0;

int main(int argc, char** argv) {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    u_char packet[PACKET_SIZE];

    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        return CANNOT_LOAD_NPCAP_ERROR_CODE;
    }

    if (argc < 3) {
        usage();
        return INSUFFICIENT_ARGS_ERROR_CODE;
    }

    // Parse the arguments from the command-line. Should receive the device-name, destination IP,
    // list of ports to scan, and number of ports to scan
    char device[DEVICE_STRING_SIZE];
    u_short ports[MAX_PORTS];
    int port_count = 0;
    u_char dest_ip_address_string[INET_ADDRSTRLEN];
    if (!parse_argv(argc, argv, device, dest_ip_address_string, ports, &port_count)) {
        return INVALID_ARGS_ERROR_CODE;
    }
    // Make duplicate of port_count so we can decrement it later when we start receiving
    // response packets
    total_ports = port_count;    
    // Get the destination IP address in bytes (u_chars)
    struct sockaddr_in sa;
    inet_pton(AF_INET, dest_ip_address_string, &(sa.sin_addr));
    dest_ip_address[0] = (u_char)(sa.sin_addr.S_un.S_un_b.s_b1);
    dest_ip_address[1] = (u_char)(sa.sin_addr.S_un.S_un_b.s_b2);
    dest_ip_address[2] = (u_char)(sa.sin_addr.S_un.S_un_b.s_b3);
    dest_ip_address[3] = (u_char)(sa.sin_addr.S_un.S_un_b.s_b4);

    // Get the source MAC address 
    u_char source_mac_address[MAC_ADAPTER_LENGTH];
    if (!get_source_adaptor_details(device, source_mac_address, source_ip_address)) {
        return SOURCE_ADAPTOR_ERROR_CODE;
    }

    // Save the source IP address
    char source_ip_address_string[IP_ADDRESS_STRING_LENGTH];
    sprintf_s(source_ip_address_string, IP_ADDRESS_STRING_LENGTH, "%d.%d.%d.%d", source_ip_address[0], source_ip_address[1], source_ip_address[2], source_ip_address[3]);
    
    // Get the destination MAC address
    u_char dest_mac_address[MAC_ADAPTER_LENGTH];
    if (!get_destination_adaptor_details(source_ip_address_string, dest_ip_address_string, dest_mac_address)) {
        return DEST_ADAPTOR_ERROR_CODE;
    }

    // Get the networking device full-name
    char device_name[200];
    if (!get_source_adaptor_full_name(device, device_name)) {
        return SOURCE_ADAPTOR_FULL_NAME_ERROR_CODE;
    }

    // Open the network adapter    
    if ((fp = pcap_open_live(device_name, 65536, 1, 1000, errorBuffer)) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter %s\n", device);
        return OPEN_ADAPTOR_ERROR_CODE;
    }
    
    // Build the packets and send
    fprintf(stdout, "Scanning for %d TCP ports...\n", port_count);
    for (int j = 0; j < port_count; j++) {
        set_ethernet_fields(packet, source_mac_address, dest_mac_address);
        set_internet_protocol_fields(packet);
        set_tcp_fields(packet, ports[j]);

        if (pcap_sendpacket(fp, packet, PACKET_SIZE) != 0) {
            fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
            return SEND_PACKET_ERROR_CODE;
        }
    }

    // Start listening for packets
    pcap_loop(fp, 0, packet_handler, NULL);

    // Close
    pcap_close(fp);

    fprintf(stdout, "\nComplete!\n");
    return SUCCESS_ERROR_CODE;
}

// Load npcap DLLs
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

// Display program usage
void usage() {
    pcap_if_t* all_devices, * device;
    char errorBuffer[PCAP_ERRBUF_SIZE];

    fprintf(stdout, "Usage: SYNSCAN.EXE Adaptor-GUID IP-Address Port1 Port2 .. PortN\n");
    fprintf(stdout, "e.g. SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 21 23 80\n");
    fprintf(stdout, "     SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 0-1024\n");
    fprintf(stdout, "     SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 0-1024 6667 1234\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "Finding available adaptors....\n");

    if (pcap_findalldevs(&all_devices, errorBuffer) == -1) {
        fprintf(stdout, "Error getting devices (pcap_findalldevs()): %s\n", errorBuffer);
        exit(1);
    }
    for (device = all_devices; device; device = device->next) {
        if (device->description) {
            fprintf(stdout, "%s\t(%s)\n", device->name, device->description);
        }
        else {
            fprintf(stdout, "%s\t(No description)\n", device->name);
        }
    }
}

BOOL parse_argv(int argc, char* argv[], char* device, char ip_address[], u_short ports[], int* port_count) {
    strcpy_s(device, DEVICE_STRING_SIZE, argv[1]);
    strcpy_s(ip_address, INET_ADDRSTRLEN, argv[2]);

    *port_count = 0;
    for (int i = 3; i < argc; i++) {
        //char* c = argv[i];
        char* e = strchr(argv[i], '-');
        if (e == NULL) {
            int port = atoi(argv[i]);
            if ((port < 1) || (port > 65535)) {
                fprintf(stderr, "%s is not a valid port number\n", argv[i]);
                return FALSE;
            }
            ports[*port_count] = (u_short)port;
            (*port_count)++;
            if (*port_count > MAX_PORTS) {
                fprintf(stderr, "Too many ports\n");
                return FALSE;
            }
        }
        else {
            char* token2 = NULL;
            char* token1 = strtok_s(argv[i], "-", &token2);
            if (token1 != NULL && token2 != NULL) {
                int low_port = atoi(token1);
                int high_port = atoi(token2);

                if ((low_port < 1) || (low_port > 65535)) {
                    fprintf(stderr, "%d is not a valid port number\n", low_port);
                    return FALSE;
                }
                if ((high_port < 1) || (high_port > 65535)) {
                    fprintf(stderr, "%d is not a valid port number\n", high_port);
                    return FALSE;
                }
                if (low_port >= high_port) {
                    fprintf(stderr, "%s is not a valid port range\n", argv[i]);
                    return FALSE;
                }

                for (int j = low_port; j <= high_port; j++) {
                    ports[*port_count] = (u_short)j;
                    (*port_count)++;
                    if (*port_count > MAX_PORTS) {
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

    DWORD size = 0;
    PIP_ADAPTER_ADDRESSES adapter_addresses, adapter_address;
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
        fprintf(stderr, "Unable to get network adaptors(GetAdaptersAddresses())");
        return FALSE;
    }
    adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &size) != ERROR_SUCCESS) {
        fprintf(stderr, "Unable to get network adaptors(GetAdaptersAddresses())");
        free(adapter_addresses);
        return FALSE;
    }

    DWORD buffer_length = 100;

    for (adapter_address = adapter_addresses; adapter_address != NULL; adapter_address = adapter_address->Next) {
        if (!strcmp(adapter_address->AdapterName, device))
        {
            found_adaptor = TRUE;
            memcpy(mac_address, adapter_address->PhysicalAddress, adapter_address->PhysicalAddressLength);

            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = adapter_address->FirstUnicastAddress;
            if (pUnicast != NULL) {
                for (int i = 0; pUnicast != NULL; i++)
                {
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        SOCKADDR_IN* sa_in = (SOCKADDR_IN*)pUnicast->Address.lpSockaddr;
                        ip_address[0] = (u_char)(sa_in->sin_addr.S_un.S_un_b.s_b1);
                        ip_address[1] = (u_char)(sa_in->sin_addr.S_un.S_un_b.s_b2);
                        ip_address[2] = (u_char)(sa_in->sin_addr.S_un.S_un_b.s_b3);
                        ip_address[3] = (u_char)(sa_in->sin_addr.S_un.S_un_b.s_b4);
                    }
                    pUnicast = pUnicast->Next;
                }
            }
        }
    }

    if (!found_adaptor) {
        fprintf(stderr, "Unable to find adaptor\n");
        return FALSE;
    }
    return TRUE;
}

// Get the full-name for the source network adaptor
BOOL get_source_adaptor_full_name(char device[], char device_full_name[]) {
    pcap_if_t* all_devices;
    pcap_if_t* device_found;
    int i = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list */
    if (pcap_findalldevs(&all_devices, error_buffer) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", error_buffer);
        return FALSE;
    }

    /* Print the list */
    for (device_found = all_devices; device_found; device_found = device_found->next)
    {
        if (strstr(device_found->name, device) != NULL) {
            strcpy_s(device_full_name, 200, device_found->name);
            pcap_freealldevs(all_devices);
            return TRUE;
        }
    }

    pcap_freealldevs(all_devices);
    return FALSE;
}

// Get the destination networking adaptor details
BOOL get_destination_adaptor_details(char* source_ip, char* dest_ip, u_char dest_mac_address[MAC_ADAPTER_LENGTH]) {
    ULONG physical_address_length = MAC_ADAPTER_LENGTH;
    u_char temp_dest_mac_address[MAC_ADAPTER_LENGTH];

    IPAddr source_ip_string = 0;
    IPAddr dest_ip_string = 0;

    if (inet_pton(AF_INET, dest_ip, &dest_ip_string) != 1) {
        return FALSE;
    }
    if (inet_pton(AF_INET, source_ip, &source_ip_string) != 1) {
        return FALSE;
    }

    if (SendARP((IPAddr)dest_ip_string, (IPAddr)source_ip_string, &temp_dest_mac_address, &physical_address_length)) {
        fprintf(stderr, "Unable to get destination ethernet address\n");
        return FALSE;
    }

    memcpy(dest_mac_address, temp_dest_mac_address, MAC_ADAPTER_LENGTH);

    return TRUE;
}

// Convert string IP into byte array
BOOL string_to_ipaddress(char* str, u_char ip_address[]) {
    struct sockaddr_in sa;

    return inet_pton(AF_INET, str, &(sa.sin_addr));
}

// Copy byte to array
void copy_u_short_to_array(u_char* array, int index, u_short val) {
    u_short val2 = htons(val);
    memcpy((array + index), (unsigned char*)&val2, sizeof(u_short));
}
// Copy long to array
void copy_u_long_to_array(u_char* array, int index, u_long val) {
    u_long val2 = htonl(val);
    memcpy((array + index), (unsigned char*)&val2, sizeof(u_long));
}

// Calcualate the IP section checksum
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

// Calculate the TCP section checksum
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

// Set the Ethernet section fields
void set_ethernet_fields(u_char packet[PACKET_SIZE], u_char source_mac_address[MAC_ADAPTER_LENGTH], u_char dest_mac_address[MAC_ADAPTER_LENGTH]) {
    /*
    Set the Ethernet section of the packet (12 bytes)
    ( https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II )

    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 |
    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    |   Destination MAC Address   |     Source MAC Address      |  Type   |
    +-----------------------------+-----------------------------+---------+
    */

    // Copy destination MAC address
    memcpy(packet + 0, dest_mac_address, MAC_ADAPTER_LENGTH);

    // Copy source MAC address
    memcpy(packet + 6, source_mac_address, MAC_ADAPTER_LENGTH);

    // EtherType 0x0800 for IPv4 https://en.wikipedia.org/wiki/EtherType#Examples
    copy_u_short_to_array(packet, 12, (u_short)ETHERNET_IPV4);
}

// Set the IP section fields
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
    packet[26] = source_ip_address[0];
    packet[27] = source_ip_address[1];
    packet[28] = source_ip_address[2];
    packet[29] = source_ip_address[3];

    // Destination IP
    packet[30] = dest_ip_address[0];
    packet[31] = dest_ip_address[1];
    packet[32] = dest_ip_address[2];
    packet[33] = dest_ip_address[3];

    // Header Checksum
    u_short ip_checksum = calculate_ip_checksum(packet);
    copy_u_short_to_array(packet, 24, ip_checksum);
}

// Set the TCP section fields
void set_tcp_fields(u_char packet[PACKET_SIZE], u_short dest_port) {
    /*
    Set the TCP section of the packet
    (https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure)

              +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
              | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 |
              +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
              |    SrcPort | DstPort |  Sequence Number  |    Ack Number     |OFST|FLGS|
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

// Handle packets received
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    if (header->len > 50) {
        if (
            (pkt_data[12] == 0x08) && (pkt_data[13] == 0x00) && //  12-13 0x0800 (IP)
            (pkt_data[14] == 0x45) &&                           //  14    0x45 (IPv4)
            (pkt_data[23] == 0x06))                             //  23    0x06 (TCP)
        {
            if (
                (pkt_data[26] == dest_ip_address[0]) &&
                (pkt_data[27] == dest_ip_address[1]) &&
                (pkt_data[28] == dest_ip_address[2]) &&
                (pkt_data[29] == dest_ip_address[3]) &&
                (pkt_data[30] == source_ip_address[0]) &&
                (pkt_data[31] == source_ip_address[1]) &&
                (pkt_data[32] == source_ip_address[2]) &&
                (pkt_data[33] == source_ip_address[3]))
            {
                u_short port = ((u_short)pkt_data[34] << 8) + pkt_data[35];
                u_short flags = ((u_short)pkt_data[46] << 8) + pkt_data[47];

                if (((flags & TCP_FLAGS_ACK) == TCP_FLAGS_ACK) && ((flags & TCP_FLAGS_SYN) == TCP_FLAGS_SYN)) {
                    fprintf(stdout, "%d - Open\n", port);
                }
                else if (((flags & TCP_FLAGS_ACK) == TCP_FLAGS_ACK) && ((flags & TCP_FLAGS_RST) == TCP_FLAGS_RST)) {
                    //fprintf(stdout, "%d - Closed\n", port);
                }
                else {
                    fprintf(stdout, "%d - Unknown\n", port);
                }

                total_ports--;
                if (total_ports == 0) {
                    pcap_breakloop(fp);
                }
            }
        }
    }
}