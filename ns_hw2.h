
//
//  ns_hw2.h
//  trial
//
//  Created by Pruthvi Madugundu on 9/27/17.
//
//  Reference - http://www.tcpdump.org/pcap.html
//  Copyright © 2017 Pruthvi Madugundu. All rights reserved.
//  This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without 
//  modification, are permitted provided that the following conditions are met:
//
//  Redistribution must retain the above copyright notice and this list of conditions.
//  The name of Tim Carstens may not be used to endorse or promote products derived from this document
//  without specific prior written permission.

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
	// can be options of 24 bits and 8 bits padding
};

struct sniff_udp 
{
	unsigned short src_port;
	unsigned short dest_port;
	unsigned short len;
	unsigned short checksum;
};


struct sniff_icmp
{
	char type;
	char code;
	short checksum;
	unsigned int header;
	// payload data is optional
};

struct sniff_igmp
{
	char type;		// higher nibble version - 1, lower type = 1-2
	char resp_time;
	short checksum;
	unsigned int group_addr;
};

