#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H
#include "headers.h"
#include "tool.h"
#include <stdio.h>
#include <pcap.h>

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

void parse_ethernet(const u_char *packet, int verbose, int prof);
void parse_arp(const u_char *packet, int verbose, int prof);
void parse_ipv4(const u_char *packet, int verbose, int prof);
void parse_ipv6(const u_char *packet, int verbose, int prof);
void parse_udp(const u_char *packet, int verbose, int prof, int size);
void parse_tcp(const u_char *packet, int verbose, int prof, int size);
void parse_icmp(const u_char *packet, int verbose, int prof);
void parse_bootp(const u_char *packet, int verbose, int prof);
void parse_dhcp(const u_char *packet, int verbose, int prof);
void print_dhcp_arg(int size, int i, const u_int8_t *bp_vend);
int dhcp_tag(struct bootp* bootp_header);
void parse_dns(const u_char *packet, int verbose, int prof, int size);
void parse_http(const u_char *packet, int verbose, int prof, int size);
void parse_ftp(const u_char *packet, int verbose, int prof, int size);
void parse_smtp(const u_char *packet, int verbose, int prof, int size);
void parse_imap(const u_char *packet, int verbose, int prof, int size);
void options_imap(const u_char *packet_arg, char * buff);
void parse_telnet(const u_char *packet, int verbose, int prof, int size);
void parse_pop3(const u_char *packet, int verbose, int prof, int size);

#endif // PACKET_PARSER_H