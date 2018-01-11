Description of the HW 2 - Network Security CS 508

Submitted by 


Reference - http://www.tcpdump.org/pcap.html and resources provided in this page.

Source file - ns_hw2_pmadugundu.cpp
Header file - ns_hw2.h
Output file - mydump

How to Build:---->
#make

How to Clean build:---->
#make clean
#make

Output File - mydump

Help---->
mydump [-i interface] [-r file] [-s string] expression

-i <interface>            -> Ethernet interface
-r <file path with name>  -> pcap file path
-s <string>               -> Packer are filter if the payload contains this "string" 
expression                -> Expression which is filtered using the BPF filter

Example run commands---->
#./mydump
-> default opens the first ethernet interface.
#./mydump -r <pcap file name>
#./mydump -i <ethernet interface name>
#./mydump -s tcp
#./mydump -s http
#./mydump -r hw1.pcap -s img
#./mydump "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0"
#./mydump -i eth0 tcp "port 80"
#./mydump -r pcapfile.pcap -s img "tcp[tcpflags] & (tcp-ack) != 0"
#./mydump -r hw1.pcap >> final_hw1_packet.txt

Note: Super user permission will be required if accessing the interface. So use "sudo"

Description of output----->

1st line
***********************************
<Timestamp of the packet> <Source MAC addr> -> <Destination MAC addr> type <Ethernet packet type in hex> len <Length of the ethernet packet>
***********************************

2nd Line
***********************************
<Source IP addr for IP packets:port> -> <Destination IP addr for IP packets:port> <Packet type> <TCP flags for only TCP packets> len <payload length>
***********************************

Note: The 2nd line is not output for ARP or raw packets.

Sample Output -------> 
1) TCP Syn packet
2013-01-14 12:48:18.471308 c4:3d:c7:17:4f:9b -> 00:0c:29:e9:94:8e type 0x800 len 74
1.234.31.20:55672 -> 192.168.0.200:80 TCP SYN dataLen = 0

2) TCP Sync Ack packet 
2013-01-14 12:48:18.471398 00:0c:29:e9:94:8e -> c4:3d:c7:17:4f:9b type 0x800 len 74
192.168.0.200:80 -> 1.234.31.20:55672 TCP SYN-ACK dataLen = 0

3) TCP Fin ACK packet
2013-01-14 12:48:18.473953 00:0c:29:e9:94:8e -> c4:3d:c7:17:4f:9b type 0x800 len 66
192.168.0.200:80 -> 1.234.31.20:52079 TCP FIN-ACK dataLen = 0

4) TCP ACK packet
2013-01-14 12:48:18.815958 c4:3d:c7:17:4f:9b -> 00:0c:29:e9:94:8e type 0x800 len 66
1.234.31.20:55672 -> 192.168.0.200:80 TCP ACK dataLen = 0

5) TCP packet with payload len = 167 bytes
2013-01-14 12:48:18.817364 c4:3d:c7:17:4f:9b -> 00:0c:29:e9:94:8e type 0x800 len 233
1.234.31.20:55672 -> 192.168.0.200:80 TCP PUSH-ACK dataLen = 167
47 45 54 20 2F 4D 79 41 64 6D 69 6E 2F 73 63 72    GET /MyAdmin/scr
69 70 74 73 2F 73 65 74 75 70 2E 70 68 70 20 48    ipts/setup.php H
54 54 50 2F 31 2E 31 0D 0A 41 63 63 65 70 74 3A    TTP/1.1..Accept:
20 2A 2F 2A 0D 0A 41 63 63 65 70 74 2D 4C 61 6E     */*..Accept-Lan
67 75 61 67 65 3A 20 65 6E 2D 75 73 0D 0A 41 63    guage: en-us..Ac
63 65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67    cept-Encoding: g
7A 69 70 2C 20 64 65 66 6C 61 74 65 0D 0A 55 73    zip, deflate..Us
65 72 2D 41 67 65 6E 74 3A 20 5A 6D 45 75 0D 0A    er-Agent: ZmEu..
48 6F 73 74 3A 20 38 36 2E 30 2E 33 33 2E 32 30    Host: 86.0.33.20
0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 43 6C    ..Connection: Cl
20 64 65 66 6C 61 74                                deflat

6) UDP packet with payload len = 289 bytes
2013-01-14 13:25:43.625245 c4:3d:c7:17:4f:9b -> 01:00:5e:7f:ff:fa type 0x800 len 331
192.168.0.1:1900 -> 239.255.255.250:1900 UDP dataLen = 289
4E 4F 54 49 46 59 20 2A 20 48 54 54 50 2F 31 2E    NOTIFY * HTTP/1.
31 0D 0A 48 6F 73 74 3A 20 32 33 39 2E 32 35 35    1..Host: 239.255
2E 32 35 35 2E 32 35 30 3A 31 39 30 30 0D 0A 43    .255.250:1900..C
61 63 68 65 2D 43 6F 6E 74 72 6F 6C 3A 20 6D 61    ache-Control: ma
78 2D 61 67 65 3D 36 30 0D 0A 4C 6F 63 61 74 69    x-age=60..Locati
6F 6E 3A 20 68 74 74 70 3A 2F 2F 31 39 32 2E 31    on: http://192.1
36 38 2E 30 2E 31 3A 31 39 30 30 2F 57 46 41 44    68.0.1:1900/WFAD
65 76 69 63 65 2E 78 6D 6C 0D 0A 4E 54 53 3A 20    evice.xml..NTS: 
73 73 64 70 3A 61 6C 69 76 65 0D 0A 53 65 72 76    ssdp:alive..Serv
65 72 3A 20 50 4F 53 49 58 2C 20 55 50 6E 50 2F    er: POSIX, UPnP/
31 2E 30 20 42 72 6F 61 64 63 6F 6D 20 55 50 6E    1.0 Broadcom UPn
50 20 53 74 61 63 6B 2F 65 73 74 69 6D 61 74 69    P Stack/estimati
6F 6E 20 31 2E 30 30 0D 0A 4E 54 3A 20 75 70 6E    on 1.00..NT: upn
70 3A 72 6F 6F 74 64 65 76 69 63 65 0D 0A 55 53    p:rootdevice..US
4E 3A 20 75 75 69 64 3A 46 35 31 39 33 39 30 41    N: uuid:F519390A
2D 34 34 44 44 2D 32 39 35 38 2D 36 32 33 37 2D    -44DD-2958-6237-
45 41 33 37 42 39 38 37 43 33 46 44 3A 3A 75 70    EA37B987C3FD::up
6E 70 3A 72 6F 6F 74 64 65 76 69 63 65 0D 0A 0D    np:rootdevice...
63                                                 c

7) Sample ARP packet output
2013-01-12 11:37:42.871346 c4:3d:c7:17:4f:9b -> ff:ff:ff:ff:ff:ff type 0x806 len 60
00 01 08 00 06 04 00 01 C4 3D C7 17 6F 9B C0 A8    .........=..o...
00 01 00 00 00 00 00 00 C0 A8 00 0C 00 00 00 00    ................
06 04 00 01 C4 3D C7 17 6F 9B C0 A8 00 01          .....=..o.....

8) Sample TCP HTTP response packet
2013-01-13 05:36:10.592137 c4:3d:c7:17:4f:9b -> 00:0c:29:e9:94:8e type 0x800 len 628
91.189.90.40:80 -> 192.168.0.200:42497 TCP PUSH-ACK dataLen = 562
48 54 54 50 2F 31 2E 30 20 32 30 30 20 4F 4B 0D    HTTP/1.0 200 OK.
0A 43 6F 6E 74 65 6E 74 2D 4C 6F 63 61 74 69 6F    .Content-Locatio
6E 3A 20 69 6E 64 65 78 2E 68 74 6D 6C 2E 65 6E    n: index.html.en
0D 0A 54 43 4E 3A 20 63 68 6F 69 63 65 0D 0A 4C    ..TCN: choice..L
61 73 74 2D 4D 6F 64 69 66 69 65 64 3A 20 4D 6F    ast-Modified: Mo
6E 2C 20 30 31 20 4F 63 74 20 32 30 31 32 20 31    n, 01 Oct 2012 1
35 3A 35 37 3A 30 39 20 47 4D 54 0D 0A 41 63 63    5:57:09 GMT..Acc
65 70 74 2D 52 61 6E 67 65 73 3A 20 62 79 74 65    ept-Ranges: byte
73 0D 0A 43 6F 6E 74 65 6E 74 2D 45 6E 63 6F 64    s..Content-Encod
69 6E 67 3A 20 67 7A 69 70 0D 0A 43 6F 6E 74 65    ing: gzip..Conte
6E 74 2D 4C 65 6E 67 74 68 3A 20 31 38 37 39 0D    nt-Length: 1879.
0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74    .Content-Type: t
65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 74 65 6E    ext/html..Conten
74 2D 4C 61 6E 67 75 61 67 65 3A 20 65 6E 0D 0A    t-Language: en..
44 61 74 65 3A 20 53 75 6E 2C 20 31 33 20 4A 61    Date: Sun, 13 Ja
6E 20 32 30 31 33 20 31 30 3A 31 36 3A 35 39 20    n 2013 10:16:59 
47 4D 54 0D 0A 53 65 72 76 65 72 3A 20 41 70 61    GMT..Server: Apa
63 68 65 2F 32 2E 32 2E 32 32 20 28 55 62 75 6E    che/2.2.22 (Ubun
74 75 29 0D 0A 45 54 61 67 3A 20 22 31 38 36 31    tu)..ETag: "1861
61 39 30 2D 31 37 38 39 2D 34 63 62 30 31 37 34    a90-1789-4cb0174
64 31 66 35 37 34 22 0D 0A 56 61 72 79 3A 20 6E    d1f574"..Vary: n
65 67 6F 74 69 61 74 65 2C 61 63 63 65 70 74 2D    egotiate,accept-
6C 61 6E 67 75 61 67 65 2C 41 63 63 65 70 74 2D    language,Accept-
45 6E 63 6F 64 69 6E 67 0D 0A 41 67 65 3A 20 31    Encoding..Age: 1
31 35 32 0D 0A 58 2D 43 61 63 68 65 3A 20 48 49    152..X-Cache: HI
54 20 66 72 6F 6D 20 61 76 6F 63 61 64 6F 2E 63    T from avocado.c
61 6E 6F 6E 69 63 61 6C 2E 63 6F 6D 0D 0A 58 2D    anonical.com..X-
43 61 63 68 65 2D 4C 6F 6F 6B 75 70 3A 20 48 49    Cache-Lookup: HI
54 20 66 72 6F 6D 20 61 76 6F 63 61 64 6F 2E 63    T from avocado.c
61 6E 6F 6E 69 63 61 6C 2E 63 6F 6D 3A 38 30 0D    anonical.com:80.
0A 56 69 61 3A 20 31 2E 31 20 61 76 6F 63 61 64    .Via: 1.1 avocad
6F 2E 63 61 6E 6F 6E 69 63 61 6C 2E 63 6F 6D 3A    o.canonical.com:
38 30 20 28 73 71 75 69 64 2F 32 2E 37 2E 53 54    80 (squid/2.7.ST
41 42 4C 45 37 29 0D 0A 43 6F 6E 6E 65 63 74 69    ABLE7)..Connecti
6F 6E 3A 20 6B 65 65 70 2D 61 6C 69 76 65 0D 0A    on: keep-alive..
2D 53                                              -S


Description of the Implementation ----->

ns_hw2_pmadugundu.cpp
Functions
1) main() -> Handles all the pcap library API calls to connect to the interface, set the filters, etc.
2) parse_args() -> Handles all the parsing of the input arguments.
3) check_packet() -> Called for each packet to parse the packet header and dump the information of the screen.
4) printpayload() -> Handles printing the payload.
5) check_search_filtering() -> Handles the payload searching for a particular string.

ns_hw2.h
Contains structure declarations.

