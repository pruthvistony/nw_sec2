//
//  ns_hw2_pmadugundu.cpp
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

#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "ns_hw2.h"
#include <time.h>
#include <ctype.h>

#define	protocol_icmp		1
#define protocol_igmp		2
#define	protocol_ipip		4
#define	protocol_tcp 		6
#define	protocol_udp		17
#define	protocol_raw		255

//struct pcap_pkthdr 
//{
//	struct timeval ts; /* time stamp */
//	bpf_u_int32 caplen; /* length of portion present */
//	bpf_u_int32 len; /* length this packet (off wire) */
//};

char device[1024];
char *pdev = NULL;
int file_input = 0;
FILE *file = NULL;

int do_search_filter = 0;		// 0 - no search, otherwise the argument number;
char search_filter[1024];
int do_exp_filter = 0;			// 0 - no exp, otherwise the argument number;

//mydump [-i interface] [-r file] [-s string] expression
int parse_args(int argc, char *argv[])
{
	int i, j;
	//char filename[1024] = {'\0'};

	if(argc < 2)
		return 0;

	for(i = 1; i < argc;)
	{
		if(!strcmp(argv[i], "-i"))
		{
			// interface is provided
			if(argv[i + 1] == NULL)
			{
				printf("Error: Interface argument is NULL, exit\n");
				return 1;
			}
			strcpy((char *)&device[0], argv[i + 1]);
			pdev = (char*) &device[0];
			printf("Interface = %s\n", argv[i + 1]);
			file_input = 0;
			i += 2;
		}
		else if(!strcmp(argv[i], "-r"))
		{
			// file is provided
			if(argv[i + 1] == NULL)
			{
				printf("Error: file argument is NULL, exit\n");
				return 1;
			}
			//strcpy(filename, argv[i+1]);
			//printf("file = %s\n", argv[i + 1]);
			printf("Opening the file = %s\n", argv[i + 1]);
			file = fopen(argv[i + 1], "r");
			if(file == NULL)
			{
				printf("Error: file open error, exiting\n");
				return 1;
			}
			i += 2;
			file_input = i - 1;
			pdev = NULL;
		}
		else if(!strcmp(argv[i], "-s"))
		{
			if(argv[i + 1] == NULL)
			{
				printf("Error: Search String argument is NULL, exit\n");
				return 1;
			}
			do_search_filter = i + 1;
			strcpy(search_filter, argv[i + 1]);
			printf("Search string = %s\n", argv[i + 1]);
			i += 2;
		}
		else
		{
			do_exp_filter = i;
			printf("Expression = %s\n", argv[i]);
			i++;
		}
	}

	return 0;
}

void printpayload(unsigned char *ptr, int len)
{
	int nline = len / 16;
	int remdata = len, i, j, rem;
	//if(len % 16 != 0)
	//	nline++;

	for(i = 0; i < nline; i++)
	{
		for(j = 0; j < 16; j++)
		{
			printf("%02X ", ptr[(i * 16) + j]);
		}
		printf("   ");

		for(j = 0; j < 16; j++)
		{
			char c = ptr[(i * 16) + j];
			if(c <= 0x1f || c == 0x7f)
				printf(".");
			else
				printf("%c", c);
		}
		printf("\n");
		remdata -= 16;
	}

	if(remdata > 0)
	{
		rem = 16 - remdata;

		for(j = 0; j < remdata; j++)
		{
			printf("%02X ", ptr[(i * nline) + j]);
		}

		for(j = 0; j < rem; j++)
		{
			printf("   ");
		}
		printf("   ");

		for(j = 0; j < remdata; j++)
		{
			char c = ptr[(i * nline) + j];
			if(c <= 0x1f || c == 0x7f)
				printf(".");
			else
				printf("%c", c);
		}
		printf("\n");
	}

	return;
}

// 1 to continue with the packet
// 0 to drop the packet;

int check_search_filtering(char *payload, int main_len)
{
	char *search = NULL;
	int slen = strlen(search_filter), i;

	if(do_search_filter == 0)		// no searching required
		return 1;

	if(main_len == 0) 
		return 0;		// drop the packet without data

	if(payload == NULL || payload[0] == '\0')// || main_len == 0)
		return 0;

	//printf("search = %s pay = %c \n", search_filter, payload[0]);
	//if(do_search_filter)
	//{
	//	search = strstr(payload, search_filter);
	//	if(search == NULL)
	//		return 0;		// no string found, so drop the packet;
	//}

	for(i = 0; i < main_len; i++)
	{
		if((i + slen) > main_len)
			return 0;

		if(strncmp((const char*)&payload[i], search_filter, slen) == 0)
			return 1;
	}

	return 0;
}

void check_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int i, len = header->len, h, l;
	char *ptr = (char*)packet, *ptime;
	struct sniff_ethernet *pethpack = NULL; 
	struct sniff_ip *pippack = NULL;
	struct sniff_tcp *ptcppack = NULL;
	struct sniff_udp *pudppack = NULL;
	struct sniff_icmp *picmppack = NULL;
	struct sniff_igmp *pigmppack = NULL;
	char *payload = NULL;
	int paysize = 0;
	struct tm *ptm;

	int ethernet_header_size = 14, ip_header_size = 20, tcp_header_size = 20;
	int udp_header_size = 8, icmp_header_size = 8, igmp_header_size = 8;		// all bytes

	//printf("Packet len = %d\n", header->len);

	pethpack = (struct sniff_ethernet*) ptr;
	pippack = (struct sniff_ip*) (ptr + ethernet_header_size);

	//ptcppack = (struct sniff_tcp*) (ptr + ethernet_header_size + ip_header_size);
	//pudppack = (struct sniff_udp*) (ptr + ethernet_header_size + ip_header_size);
	//picmppack = (struct sniff_icmp*) (ptr + ethernet_header_size + ip_header_size);
	//pigmppack = (struct sniff_igmp*) (ptr + ethernet_header_size + ip_header_size);


	// get the protocol
	// get the payload if any
	// search for the -s string, if found print all the data in format

	//i = pethpack->ether_type;
	//printf("type 0x%d ", pethpack->ether_type);

	// swap the ethernet type bytes
	l = (pethpack->ether_type >> 8) & 0xff;
	h = ((pethpack->ether_type & 0xff) << 8);
	//printf("h = %x l = %x ", h, l);
	pethpack->ether_type = h | l;

	//return;

	if(pethpack->ether_type == 0x800)
	{
		//printf("iplen = %d IP packet header = %d, tot = %d macro = %d \n", pippack->ip_len, (pippack->ip_vhl & 0xf) * 4, len, ip_header_size);
		ip_header_size = (pippack->ip_vhl & 0xf) * 4;
		switch(pippack->ip_p)
		{
			case protocol_icmp:
				picmppack = (struct sniff_icmp*) (ptr + ethernet_header_size + ip_header_size);
				payload = (char*) (ptr + ethernet_header_size + ip_header_size + icmp_header_size);
				len = len - (ethernet_header_size + ip_header_size + icmp_header_size);
				
				if((do_search_filter != 0) && (len == 0))
					return;

				if(check_search_filtering(payload, len) == 0)
					return;

				break;

			case protocol_igmp:
				pigmppack = (struct sniff_igmp*) (ptr + ethernet_header_size + ip_header_size);
				payload = (char*) (ptr + ethernet_header_size + ip_header_size + igmp_header_size);
				len = len - (ethernet_header_size + ip_header_size + igmp_header_size);
				
				if((do_search_filter != 0) && (len == 0))
					return;

				if(check_search_filtering(payload, len) == 0)
					return;

				break;

			case protocol_ipip:
				payload = (char*) (ptr + ethernet_header_size + ip_header_size + ip_header_size);
				len = len - (ethernet_header_size + ip_header_size + ip_header_size);
				
				if((do_search_filter != 0) && (len == 0))
					return;

				if(check_search_filtering(payload, len) == 0)
					return;

				break;

			case protocol_tcp:
				ptcppack = (struct sniff_tcp*) (ptr + ethernet_header_size + ip_header_size);
				tcp_header_size = ((ptcppack->th_offx2 & 0xf0) >> 4) * 4;

				payload = (char*) (ptr + ethernet_header_size + ip_header_size + tcp_header_size);
				len = len - (ethernet_header_size + ip_header_size + tcp_header_size);
				//printf("TCP packet header = %d, tot = %d macro = %d \n", ((ptcppack->th_offx2 & 0xf0) >> 4) * 4, len, tcp_header_size);
				
				if((do_search_filter != 0) && (len == 0))
					return;

				if(check_search_filtering(payload, len) == 0)
					return;

				break;

			case protocol_udp:
				pudppack = (struct sniff_udp*) (ptr + ethernet_header_size + ip_header_size);
				payload = (char*) (ptr + ethernet_header_size + ip_header_size + udp_header_size);
				len = len - (ethernet_header_size + ip_header_size + udp_header_size);

				if((do_search_filter != 0) && (len == 0))
					return;

				if(check_search_filtering(payload, len) == 0)
					return;

				break;

			case protocol_raw:
				break;

			default:
				break;
		}
	}

	if(pethpack->ether_type != 0x800)
	{
		//printf("ARP\n");
		// check raw packets for string, if not found drop it
		payload = (char*) (ptr + ethernet_header_size);

		if((do_search_filter != 0) && (header->len - ethernet_header_size == 0))
			return;

		if(check_search_filtering(payload, header->len - ethernet_header_size) == 0)
			return;
	}

	//ptime = ctime(&header->ts.tv_sec);
	ptm = localtime(&header->ts.tv_sec);
	//2016-02-16 13:14:33.224487 01:00:5E:7F:FF:7F -> C4:3D:C7:17:6F:17 type 0x800 len 92
	//10.0.0.1:137 -> 10.0.0.255:137 UDP
	//EB 71 01 10 00 01 00 00 00 00 00
	// time stamp
	printf("%d-%02d-%02d %02d:%02d:%02d.%ld ", 1900 + ptm->tm_year, 1 + ptm->tm_mon, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec, header->ts.tv_usec);
	//printf("\ntime = %s\n", ptime);
	
	// src mac and dest mac
	for(i = 0; i < 5; i++)
		printf("%02x:", toupper(pethpack->ether_shost[i]));
	printf("%02x -> ", toupper(pethpack->ether_shost[5]));
	for(i = 0; i < 5; i++)
		printf("%02x:", toupper(pethpack->ether_dhost[i]));
	printf("%02x ", toupper(pethpack->ether_dhost[5]));

	// type and len
	printf("type 0x%x ", pethpack->ether_type);
	printf("len %d\n", header->len);

	if(pethpack->ether_type != 0x800)
	{
		//printf("ARP\n");
		payload = (char*) (ptr + ethernet_header_size);
		printpayload((unsigned char*)payload, header->len - ethernet_header_size);

		printf("\n");
		return;
	}
	// src and dest ip
	//char *inet_ntoa(struct in_addr in);
	if(pippack->ip_p == protocol_tcp)		// from tcp packet we get ports numbers
	{
		printf("%s:%d ->", inet_ntoa(pippack->ip_src), ntohs(ptcppack->th_sport));
		printf(" %s:%d ", inet_ntoa(pippack->ip_dst), ntohs(ptcppack->th_dport));
	}
	else if(pippack->ip_p == protocol_udp)
	{
		printf("%s:%d ->", inet_ntoa(pippack->ip_src), ntohs(pudppack->src_port));
		printf(" %s:%d ", inet_ntoa(pippack->ip_dst), ntohs(pudppack->dest_port));
	}
	else		// normal without port infos
	{
		printf("%s ->", inet_ntoa(pippack->ip_src));
		printf(" %s ", inet_ntoa(pippack->ip_dst));
	}

	switch(pippack->ip_p)
	{
		case protocol_icmp:
			printf("ICMP dataLen = %d\n", len);
			break;

		case protocol_igmp:
			printf("IGMP dataLen = %d\n", len);
			break;

		case protocol_ipip:
			printf("IP dataLen = %d\n", len);
			break;

		case protocol_tcp:
			// add the ack or syn printing here
			printf("TCP ");
			if(ptcppack->th_flags == TH_ACK)
				printf("ACK ");
			else if(ptcppack->th_flags == TH_SYN)
				printf("SYN ");
			else if(ptcppack->th_flags == TH_RST)
				printf("RST ");
			else if(ptcppack->th_flags == TH_FIN)
				printf("FIN ");
			else if(ptcppack->th_flags == (TH_ACK|TH_SYN))
				printf("SYN-ACK ");
			else if(ptcppack->th_flags == (TH_PUSH|TH_ACK))
				printf("PUSH-ACK ");
			else if(ptcppack->th_flags == (TH_FIN|TH_ACK))
				printf("FIN-ACK ");
			else
				printf("Flag = 0x%x ", ptcppack->th_flags);

			printf("dataLen = %d\n", len);
			break;

		case protocol_udp:
			printf("UDP dataLen = %d\n", len);
			break;

		case protocol_raw:
			break;

		default:
			break;
	}

	// the packet info
	//printf("pay len = %d ", len);
	printpayload((unsigned char*)payload, len);

	//printpayload((unsigned char*)"hellow\rorlds\nlkdjflksdklfs\njdflkjweorijlksdjfojewr\rkjdsfljsdklfjsdflkj", 70);
	printf("\n");
	return;
}

//pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *fp,
//    u_int precision, char *errbuf);  PCAP_TSTAMP_PRECISION_MICRO
int main(int argc, char *argv[])
{
	//char device[1024];//, *pdev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *des;
	int err = 0;
	struct bpf_program fp;	
	bpf_u_int32 mask;
	bpf_u_int32 net;

	err = parse_args(argc, argv);
	if(err != 0)
		return 1; 			// error is command parsing

    if(file_input == 0)		// read from the ethernet device
    {
    	if(pdev == NULL)
    	{
			pdev = pcap_lookupdev(errbuf);
			if(pdev == NULL)
			{
				printf("Not able to find the default device\n");
				return 1;
			}
		}

		// open the device
		printf("Opening the device = %s\n", pdev);

	    des = pcap_open_live(pdev, BUFSIZ, 1, 1024, errbuf);
	    if(des == NULL)
	    {
	    	printf("Not able to open the device = %s error = %s\n", pdev, errbuf);
	    	return 1;
	    }

	    //set the timestamp precision
	    pcap_set_tstamp_precision(des, PCAP_TSTAMP_PRECISION_MICRO);

	    if (pcap_datalink(des) != DLT_EN10MB) 
	    {
			printf("Error: Not an Ethernet\n");
			return 1;
		}

	    if(pcap_lookupnet(pdev, &net, &mask, errbuf) == -1) 
	    {
			printf("Error: Can't get netmask for device %s error = %s\n", pdev, errbuf);
			//net = 0;
			//mask = 0;
			return 1;
		}

		if(do_exp_filter != 0)
		{
			if (pcap_compile(des, &fp, argv[do_exp_filter], 0, net) == -1) 
			{
				printf("Could not parse filter %s error = %s\n", argv[do_exp_filter], pcap_geterr(des));
				return 1;
			}
			if (pcap_setfilter(des, &fp) == -1) 
			{
				printf("Could not install filter %s error = %s\n", argv[do_exp_filter], pcap_geterr(des));
				return 1;
			}
		}

	    pcap_loop(des, -1, check_packet, NULL);

	    return 0;
	}

	if(file_input > 0 && pdev == NULL)
	{
		struct pcap_pkthdr *header = NULL;
		u_char *packet = NULL;

		des = pcap_fopen_offline_with_tstamp_precision(file, PCAP_TSTAMP_PRECISION_MICRO, errbuf);

		if(des == NULL)
	    {
	    	printf("Not able to open the file for pcap parsing error = %s error = %s \n", pdev, errbuf);
	    	return 1;
	    }

	    // pcap_datalink()

	    //if(pcap_lookupnet(pdev, &net, &mask, errbuf) == -1) 
	    //{
		//	printf("Error: Can't get netmask for device %s error = %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		//}

	    if(do_exp_filter != 0)
		{
			if (pcap_compile(des, &fp, argv[do_exp_filter], 0, net) == -1) 
			{
				printf("Could not parse filter %s error = %s\n", argv[do_exp_filter], pcap_geterr(des));
				return 1;
			}
			if (pcap_setfilter(des, &fp) == -1) 
			{
				printf("Could not install filter %s error = %s\n", argv[do_exp_filter], pcap_geterr(des));
				return 1;
			}
		}

		while(1)
		{
			err = pcap_next_ex(des, &header, (const u_char **)&packet);
			if(err < 0)		// -2 end of file , -1 - error
				return 0;

			check_packet(NULL, header, packet);
		}

	}


	return 0;
}