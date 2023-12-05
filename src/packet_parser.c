#include <stdio.h>
#include "packet_parser.h"

void parse_ethernet(const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    // Traitement de l'en-tete Ethernet ici
}

void parse_ip(const u_char *packet) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
    // Traitement de l'en-tete IP ici
}

void parse_udp(const u_char *packet) {
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    // Traitement de l'en-tete UDP ici
}

void parse_tcp(const u_char *packet) {
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    // Traitement de l'en-tete TCP ici
}

void parse_icmp(const u_char *packet) {
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    // Traitement de l'en-tete ICMP ici
}

void parse_arp(const u_char *packet) {
    struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
    // Traitement de l'en-tete ARP ici
}

void parse_bootp(const u_char *packet) {
    struct bootp_header *bootp_header = (struct bootp_header *)(packet + sizeof(struct iphdr));
    // Traitement de l'en-tete BOOTP ici
}

void parse_dhcp(const u_char *packet) {
    struct dhcp_header *dhcp_header = (struct dhcp_header *)(packet + sizeof(struct iphdr));
    // Traitement de l'en-tete DHCP ici
}

void parse_dns(const u_char *packet) {
    struct dns_header *dns_header = (struct dns_header *)(packet + sizeof(struct iphdr));
    // Traitement de l'en-tete DNS ici
}

void parse_http(const u_char *packet) {
    struct http_header *http_header = (struct http_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete HTTP ici
}

void parse_ftp(const u_char *packet) {
    struct ftp_header *ftp_header = (struct ftp_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete FTP ici
}

void parse_smtp(const u_char *packet) {
    struct smtp_header *smtp_header = (struct smtp_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete SMTP ici
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    parse_ethernet(packet);
    parse_ip(packet);
    parse_udp(packet);
    parse_tcp(packet);
    parse_icmp(packet);
    parse_arp(packet);
    parse_bootp(packet);
    parse_dhcp(packet);
    parse_dns(packet);
    parse_http(packet);
    parse_ftp(packet);
    parse_smtp(packet);
}
