# SYNScan
A command-line port scanner using raw SYN packets

When initiating a legitimate TCP/IP connection, the source machine will send to the destination machine a very small packet of data which contains two important pieces of information. Firstly it will contain the destination port number we wish to connect to (80 for HTTP, 21 for FTP etc.). Secondly, in the header of the TCP section of the packet, the `Flags` byte will have the 7th bit set to signify SYN. If the destination machine has a service running on the port we requested, it will send a packet back with both the 7th (SYN) and 4th (ACKNOWLEDGE) bits set. The source machine will send another packet with the 4th (ACKNOWLEDGE) bit set, after which the destination machine will allocate resources to keep the communication channel open between the two machines so that data can be sent back and forth. If the port is closed, the 7th (SYN) and 6th (RESET) will be set, and the source machine will not send any further packets.

When scanning a host for open ports, Hackers would traditionally only send the first part of the exchange (send SYN, receive SYN/ACK for open ports or SYN/RST for closed ports) and then not respond any further. Because the port was never fully opened, firewalls would not inform the admin that the host was being scanned. SYN packets are also commonly used as part of a Distributed Denial of Service (DDoS) attack, whereby millions of SYN-packets are sent spoofed source-IP fields to a single host, quickly exhausting the resources of the target machine.

As always, this project was simply created so that I could pollish by C programming skills, and to experiment with the NPCAP library. If you need a real port-scanner that supports SYN-scanning and a whole host of other neat stuff, download [NMAP](https://nmap.org/).

Technical Information

Because we are using raw sockets, we need to manually create the Ethernet, Internet Protocol, and Transmition Control Protocol sections of the packet.

Ethernet

```
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	| 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 |
	+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	|   Destination MAC Address   |     Source MAC Address      |  Type   |
	+-----------------------------+-----------------------------+---------+
```

The Ethernet section of the packet simply consists of 6 bytes for the destination MAC Address, 6 bytes for the source MAC Address, and a 16-bit word for specifying the type. The packet type is easy enough to set (0x0800 for TCP in our case), as is the source MAC Address, which can be read from `GetAdaptersAddresses()`, but the destination MAC Address is slightly more tricky.

To get the destination MAC Address we need to use `SendARP()` to send an ARP request for the MAC Address for the destination IP Address. If the IP is inside our network `SendARP` will tell us the MAC Address associated with the device, or if the destination IP is outside our LAN (e.g. out there on The Internet), it will return the MAC Address of our router.

More information on the Ethernet section of the packet can be found on [Wikipedia](https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II)

Internet Protocol

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

Most fields in the IP section are easy enough to define, source IP, destination IP etc. The one exception is the `Checksum` field. For calculating this field we first need to set the  field to zero and then calculate the sum of the 10 words starting at offset 14. Once totalled, we repeatedly add any carried digits (those too large to fit in 16-bits) until the final value does fit in 16-bits. Finally, we return the bitwise not of the word.

More information on the Internet Protocol section of the packet can be found on [Wikipedia](https://en.wikipedia.org/wiki/IPv4#Header) which also has an article on the [IPv4 Checksum](https://en.wikipedia.org/wiki/IPv4_header_checksum)

Transmition Control Protocol

```
	          +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	          | 34 | 35 | 36 | 37 | 38 | 39 | 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 |
	          +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
	          |	SrcPort | DstPort |  Sequence Number  |    Ack Number     |OFST|FLGS|
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