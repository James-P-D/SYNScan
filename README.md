# SYNScan
A command-line port scanner using raw SYN packets

![Screenshot](https://github.com/James-P-D/SYNScan/blob/master/Screenshot.gif)

## Introduction

Legitimate TCP/IP connections always begin with what is called a SYN-ACK handshake which initialises the connection. The source machine will send to the destination machine a very small packet of data which contains two important pieces of information. Firstly it will contain the destination port number we wish to connect to (80 for HTTP, 21 for FTP etc.) Secondly, in the header of the TCP section of the packet, the `Flags` byte will have the 7th bit set to signify SYN. If the destination machine has a service running on the port we requested, it will send a packet back with both the 7th (SYN for Syncronise) and 4th (ACK for Acknowledgement) bits set. The source machine will send another packet with the 4th (ACK) bit set, after which the destination machine will allocate resources to keep the communication channel open between the two machines so that data can be sent back and forth. If the port is closed, the 7th (SYN) and 6th (RST for Reset) will be set, and the source machine will not send any further packets.

When scanning a host for open ports, Hackers would traditionally only send the first part of the exchange (send SYN, receive SYN/ACK for open ports or SYN/RST for closed ports) and then not respond any further. Because the port was never fully opened, firewalls would not inform the admin that the host was being scanned. Lone SYN packets are also commonly used as part of a Distributed Denial of Service (DDoS) attack, whereby millions of SYN-packets are sent from an array of compromised machines to a target machine, with each SYN packet containing a fraudulently spoofed source IP address. Since the source IP changes for each SYN packet sent, the target machine is unable to block the sender and quickly runs out of resources attempting to keep a large number of connections open.

As always, this project was simply created so that I could polish by C programming skills, and to experiment with the [Npcap](https://nmap.org/npcap/) library.

If you need a real port-scanner that supports SYN-scanning and a whole host of other neat stuff, download [Nmap](https://nmap.org/).

## Contents

* [Technical Information](#Technical-Information)
* [Ethernet](#Ethernet)
* [Internet Protocol](#Internet-Protocol)
* [Transmition Control Protocol](#Transmition-Control-Protocol)
* [Setup](#Setup)
* [Usage](#Usage)

## Technical Information

Because we are using raw sockets, we need to manually create the Link-layer (Ethernet), Internet-layer (Internet Protocol), and Transport-layer (Transmition Control Protocol) sections of the packet.

## Ethernet

```
    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 |
    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    |   Destination MAC Address   |     Source MAC Address      |  Type   |
    +-----------------------------+-----------------------------+---------+
```

The Ethernet section of the packet simply consists of 6 bytes for the destination MAC Address, 6 bytes for the source MAC Address, and a 16-bit word for specifying the type. The packet type is easy enough to set (0x0800 for TCP in our case), as is the source MAC Address, which can be read from `GetAdaptersAddresses()`, but the destination MAC Address is slightly more tricky.

To get the destination MAC Address we need to use `SendARP()` to send an [ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) request for the MAC Address for the destination IP. If the dsetination IP is inside our network `SendARP()` will tell us the MAC Address associated with the device, or if the destination IP is outside our LAN (i.e. out there on The Internet), it will return the MAC Address of our router.

More information on the Ethernet section of packets can be found on [Wikipedia](https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II)

## Internet Protocol

```
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
```

Most fields in the IP section are easy enough to define, source IP, destination IP etc. The one exception is the `Checksum` field. For calculating this field we first need to set the field to zero and then calculate the sum of the 10 words starting at offset 14. Once totalled, we repeatedly add any carried digits (those too large to fit in 16-bits) until the final value does fit in 16-bits. Finally, we return the bitwise not of the word.

More information on the Internet Protocol section of the packet can be found on [Wikipedia](https://en.wikipedia.org/wiki/IPv4#Header) which also has an article on the [IPv4 Checksum](https://en.wikipedia.org/wiki/IPv4_header_checksum)

## Transmition Control Protocol

```
              +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
              | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 |
              +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
              | SrcPort | DstPort |  Sequence Number  |    Ack Number     |OFST|FLGS|
    +----+----+----+----+----+----+----+----+----+----+-------------------+----+----+
    | 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 |
    +----+----+----+----+----+----+----+----+----+----+
    |  WSize  | ChkSum  | UrgtPtr | K  | L  | DegSize |
    +---------+---------+---------+----+----+---------+
```

For the TCP section, again, most fields are pretty straight-forward and can be hard-coded or set statically. The first exception is the `Flags` field at offset 47. This byte must have the 7th bit set for it to be treated as a SYN packet. 

```
    +----+----+----+----+----+----+----+----+----+----+----+----+
    | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 |
    +----+----+----+----+----+----+----+----+----+----+----+----+
    |     Source IP     |      Dest IP      |0x00|PTCL| Length  |    
    +-------------------+-------------------+----+----+---------+
```

The source and destination IPs can be copied from the IP section of the packet at offsets 26 and 30 respectively. The 8th byte is reserved so can be left as zero, whilst the 9th byte simply copies the protocol field from offset 23 in the IP section (0x06 for TCP). Finally the last word is reserved for 

More information on the TCP section of the packet can be found on [Wikipedia](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure). Also [this](https://www.securitynik.com/2015/08/calculating-udp-checksum-with-taste-of_3.html) article explains the TCP Checksum and Pseudo-Header structure.

## Setup

Getting the program running should be pretty straight-forward. Simply download the latest [Npcap SDK](https://nmap.org/npcap/) and unpack it. I chose to unpack it to `c:\npcap-sdk-1.03`, so if you choose a different location, or you download a version other than 1.03, remember to update the `Configuration Properties > C\C++ > Additional Include Directories` and `Configuration Properties > Linker > Additional Library Directories` fields in Visual Studio.

![Screenshot](https://github.com/James-P-D/SYNScan/blob/master/properties1.png)

![Screenshot](https://github.com/James-P-D/SYNScan/blob/master/properties2.png)

## Usage

After successfully compiling, run `SYNScan.exe` from the command-prompt and you'll receive something like this:

```
Usage: SYNSCAN.EXE Adaptor-GUID IP-Address Port1 Port2 .. PortN
e.g. SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 21 23 80
     SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 0-1024
     SYNSCAN.EXE (Adaptor-GUID) 127.0.0.1 0-1024 6667 1234

Finding available adaptors....
\Device\NPF_{0334126B-0AC9-4ADD-BB40-9C2885480BD3}      (NdisWan Adapter)
\Device\NPF_{47E44562-53D5-4D4E-AA26-E27CFD10E027}      (NdisWan Adapter)
\Device\NPF_{904E3F79-DD8A-45D6-B493-A362D0265A27}      (Microsoft)
\Device\NPF_{77C0922B-D5D4-452A-9631-E47DDAA3AD48}      (Microsoft)
\Device\NPF_{164722D9-BD89-43BC-A0EE-25CBF3D08C64}      (Microsoft)
\Device\NPF_{A5FA3DC8-DC13-4C66-9623-0AFE17DA6B72}      ()
\Device\NPF_{C22979EC-E91D-4D5E-82DA-1119CB7F0904}      (NdisWan Adapter)
\Device\NPF_Loopback    (Adapter for loopback traffic capture)
```

Copy the relevant network adaptor GUID to the clipboard and then run the following:

```
C:\>SYNScan.exe {904E3F79-DD8A-45D6-B493-A362D0265A27} 192.168.0.1 21 23 53 80 
```

This will scan the IP address `192.168.0.1` for open TCP ports for the [FTP](https://en.wikipedia.org/wiki/File_Transfer_Protocol), [Telnet](https://en.wikipedia.org/wiki/Telnet), [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) and [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol) services. The expected output will vary depending on the IP address you are scanning, but should generally look something like this:

```
C:\>SYNScan.exe {904E3F79-DD8A-45D6-B493-A362D0265A27} 192.168.0.1 21 23 53 80

Scanning for 4 TCP ports...
21 - Closed
23 - Closed
53 - Open
80 - Open

Complete!

C:\>
```