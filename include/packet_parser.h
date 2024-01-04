#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H
#include "headers.h"
#include "tool.h"
#include <stdio.h>
#include <pcap.h>

void parse_ethernet(const u_char *packet, int verbose, int prof);
void parse_arp(const u_char *packet, uint8_t *ether_dhost, uint8_t *ether_shost, int verbose, int prof);
void parse_ipv4(const u_char *packet, int verbose, int prof);
void parse_ipv6(const u_char *packet, int verbose, int prof);
void parse_udp(const u_char *packet, int verbose, int prof, int size);
void parse_tcp(const u_char *packet, int verbose, int prof, int size);
void parse_icmp(const u_char *packet, int verbose, int prof);
void parse_bootp(const u_char *packet, int verbose, int prof);
void parse_dhcp(const u_char *packet, int verbose, int prof);
void parse_dns(const u_char *packet, int verbose, int prof);
void parse_http(const u_char *packet, int verbose, int prof, int size);
void parse_ftp(const u_char *packet, int verbose, int prof);
void parse_smtp(const u_char *packet, int verbose, int prof);
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet, int verbose, int prof);

#endif // PACKET_PARSER_H