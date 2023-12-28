#include <stdio.h>
#include "packet_parser.h"
#include "tool.h"

void parse_ethernet(const u_char *packet, int verbose, int prof) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    print_new_state(prof);
    printf("ETHERNET :\n");
    print_tree(prof);
    printf("MAC Source : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            eth_header->ether_shost[0], eth_header->ether_shost[1],
            eth_header->ether_shost[2], eth_header->ether_shost[3],
            eth_header->ether_shost[4], eth_header->ether_shost[5]);
    print_tree(prof);
    printf("MAC Destination : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            eth_header->ether_dhost[0], eth_header->ether_dhost[1],
            eth_header->ether_dhost[2], eth_header->ether_dhost[3],
            eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    print_tree(prof);
    printf("type : %#2x \n", ntohs(eth_header->ether_type));

    // Affichage du reste de la trame
    switch (ntohs(eth_header->ether_type)) {
    case ETHERTYPE_ARP: // 0x0806
        //parse_arp(packet + sizeof(struct ether_header), eth_header->ether_dhost,
        //            eth_header->ether_shost, verbose, prof+1);
        break;

    case ETHERTYPE_IP: // 0x0800
        parse_ipv4(packet + sizeof(struct ether_header), verbose, prof+1);
        break;

    case ETHERTYPE_IPV6: // 0x08dd
        parse_ipv6(packet + sizeof(struct ether_header), verbose, prof+1);
        break;
    default:
        break;    
    }
}

void parse_ipv4(const u_char *packet, int verbose, int prof) {
    struct ip *ip = (struct ip *)(packet);

    switch(verbose) {
    case 1:
        print_new_state(prof); printf("IPV4 \n");
        break;
    case 2:
        print_new_state(prof); printf("IPV4 :\n");
        print_tree(prof); printf("@IP source  : %s | ", 
                                    inet_ntoa(*(struct in_addr *)&ip->ip_src));
        print_tree(prof); printf("@IP dest  : %s\n", 
                                    inet_ntoa(*(struct in_addr *)&ip->ip_dst));
        break;
    
    case 3:
        print_new_state(prof); printf("IPV4 :\n");
        print_tree(prof); printf("IP source : %s\n", inet_ntoa(ip->ip_src));
        print_tree(prof); printf("IP dest : %s\n", inet_ntoa(ip->ip_dst));
        print_tree(prof); printf("IP version : %i\n", ip->ip_v);
        print_tree(prof); printf("IP header length : %i (%i bytes)\n", 
                                    ip->ip_hl, ip->ip_hl * 4);
        print_tree(prof); printf("Type of Service : %i\n", ip->ip_tos);
        print_tree(prof); printf("Total length : %u\n", ntohs(ip->ip_len));
        print_tree(prof); printf("Transaction id : 0x%.2x\n",
                                    ntohs(ip->ip_id));
        print_tree(prof); printf("Fragment offset field : 0x%.2x\n", 
                                    ntohs(ip->ip_off));
        print_tree(prof); printf("Checksum : 0x%x\n", ntohs(ip->ip_sum));
        print_tree(prof); printf("Time to live : %i\n", ip->ip_ttl);
        break;
    }

    int size = ntohs(ip->ip_len) - ip->ip_hl * 4;
    switch (ip->ip_p) {
    case 0x11:
        parse_udp(packet + (ip->ip_hl * 4), verbose, prof +1, size);
        break;
    case 0x06:
        parse_tcp(packet + (ip->ip_hl * 4), verbose, prof +1, size);
        break;
    case 0x01:
        print_new_state(prof); printf("ICMP \n");
        break;
    }
}

void parse_ipv6(const u_char *packet, int verbose, int prof) {
    struct ip6_hdr *ip = (struct ip6_hdr *)(packet);
    switch (verbose) {
    case 1:
        print_new_state(prof); printf("IPV6 \n");
        break;
    case 2:
        print_new_state(prof); printf("IPV6 :\n");
        print_tree(prof); printf("IP source  : ");
        affiche_addr_ipv6(ip->ip6_src);
        
        print_tree(prof); printf("IP dest  : ");
        affiche_addr_ipv6(ip->ip6_src);
        break;
    case 3:
        print_new_state(prof); printf("IPV6 :\n");
        print_tree(prof); printf("IP source  : ");
        affiche_addr_ipv6(ip->ip6_src);
        
        print_tree(prof); printf("IP dest  : ");
        affiche_addr_ipv6(ip->ip6_src);
        
        print_tree(prof); printf("Flow : %.2x\n", ip->ip6_flow >> 8);
        print_tree(prof); printf("Payload Length : %u\n", ntohs(ip->ip6_plen));
        print_tree(prof); printf("Next header : 0x%x\n", ip->ip6_nxt);
        print_tree(prof); printf("Hop limit : %u\n", ip->ip6_hlim);
        print_tree(prof); printf("Version : %u\n", ip->ip6_vfc >> 4);
        print_tree(prof); printf("Traffic class : 0x%.2x\n", ip->ip6_flow >> 8);
        break;
    }
    int size = ntohs(ip->ip6_plen);
    switch (ip->ip6_nxt) {
    case 0x11:
        parse_udp(packet + sizeof(struct ip6_hdr), verbose, prof +1, size);
        break;
    case 0x06:
        parse_tcp(packet + sizeof(struct ip6_hdr), verbose, prof +1, size);
        break;
    case 0x3a:
        print_new_state(prof); printf("ICMPv6\n");
        break;
    }
}

void parse_udp(const u_char *packet, int verbose, int prof, int size) {
    //struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    // Traitement de l'en-tete UDP ici
}

void parse_tcp(const u_char *packet, int verbose, int prof, int size) {
    //struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    // Traitement de l'en-tete TCP ici
}

void parse_icmp(const u_char *packet, int verbose, int prof) {
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    // Traitement de l'en-tete ICMP ici
}

void parse_arp(const u_char *packet, int verbose, int prof) {
    struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
    // Traitement de l'en-tete ARP ici
}

void parse_bootp(const u_char *packet, int verbose, int prof) {
    struct bootp_header *bootp_header = (struct bootp_header *)(packet + sizeof(struct iphdr));
    // Traitement de l'en-tete BOOTP ici
}

void parse_dhcp(const u_char *packet, int verbose, int prof) {
    struct dhcp_header *dhcp_header = (struct dhcp_header *)(packet + sizeof(struct iphdr));
    // Traitement de l'en-tete DHCP ici
}

void parse_dns(const u_char *packet, int verbose, int prof) {
    struct dns_header *dns_header = (struct dns_header *)(packet + sizeof(struct iphdr));
    // Traitement de l'en-tete DNS ici
}

void parse_http(const u_char *packet, int verbose, int prof) {
    struct http_header *http_header = (struct http_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete HTTP ici
}

void parse_ftp(const u_char *packet, int verbose, int prof) {
    struct ftp_header *ftp_header = (struct ftp_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete FTP ici
}

void parse_smtp(const u_char *packet, int verbose, int prof) {
    struct smtp_header *smtp_header = (struct smtp_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete SMTP ici
}

