#include <stdio.h>
#include "packet_parser.h"
#include "tool.h"

void parse_ethernet(const u_char *packet, int verbose, int prof) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    switch(verbose) {
    case 1:
        print_new_state(prof); printf("ETHERNET \n");
        break;

    case 2:
        print_new_state(prof);
        printf("ETHERNET :\n");
        print_tree(prof);
        printf("MAC Source : ");
        print_mac(eth_header->ether_shost); printf("\n");
        print_tree(prof);
        printf("MAC Destination : ");
        print_mac(eth_header->ether_dhost); printf("\n");
        break;

    case 3:
        print_new_state(prof);
        printf("ETHERNET :\n");
        print_tree(prof);
        printf("MAC Source : ");
        print_mac(eth_header->ether_shost); printf("\n");
        print_tree(prof);
        printf("MAC Destination : ");
        print_mac(eth_header->ether_dhost); printf("\n");
        print_tree(prof);
        printf("type : %#2x \n", ntohs(eth_header->ether_type));
        break;
    }

    // Rest of the packet (protocol under Ethernet)
    switch (ntohs(eth_header->ether_type)) {
    case ETHERTYPE_ARP: // 0x0806
        parse_arp(packet + sizeof(struct ether_header), eth_header->ether_dhost,
                    eth_header->ether_shost, verbose, prof+1);
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

void parse_arp(const u_char *packet, uint8_t *ether_dhost, uint8_t *ether_shost, int verbose, int prof) {
    struct ether_arp *arp_header = (struct ether_arp *)packet;
    switch (verbose) {
    case 1:
        print_new_state(prof); printf("ARP \n");
        break; 
    case 2: 
        print_new_state(prof); printf("ARP :\n");
        print_tree(prof); printf("MAC Source : ");
        print_mac(arp_header->arp_sha);
        print_tree(prof); printf("MAC Destination : ");
        print_mac(arp_header->arp_tha);

        break;
    case 3:
        print_new_state(prof); printf("ARP :\n");
        print_tree(prof); printf("MAC Source : ");
        print_mac(arp_header->arp_sha);
        print_tree(prof); printf("MAC Destination : ");
        print_mac(arp_header->arp_tha);

        print_tree(prof); printf("Hardware type : %i", ntohs(arp_header->ea_hdr.ar_hrd));
        //TAG for the user's lisibility
        switch (ntohs(arp_header->ea_hdr.ar_hrd)) {
        case ARPHRD_ETHER:
            printf(" (Ethernet)\n");
            break;
        case ARPHRD_IEEE802:
            printf(" (Token Ring)\n");
            break;
        case ARPHRD_DLCI:
            printf(" (Frame Relay)\n");
            break;
        case ARPHRD_IEEE1394:
            printf(" (Firewire)\n");
            break;
        case ARPHRD_ARCNET:
            printf(" (ARCNET)\n");
            break;
        default:
            printf(" (Unknown)\n");
            break;
        }

        print_tree(prof); printf("Protocol type : %i", ntohs(arp_header->ea_hdr.ar_pro));
        //TAG for the user's lisibility
        switch (ntohs(arp_header->ea_hdr.ar_pro)) {
        case ETHERTYPE_IP: // 0x0800
            printf(" (IP)\n");
            break;
        case ETHERTYPE_IPV6: // 0x08dd
            printf(" (IPv6)\n");
            break;
        default:
            printf("\n");
            break;
        }

        print_tree(prof); printf("Hardware size : %i\n", arp_header->ea_hdr.ar_hln);
        print_tree(prof); printf("Protocol size : %i\n", arp_header->ea_hdr.ar_pln);
        print_tree(prof); printf("Opcode : %i\n", ntohs(arp_header->ea_hdr.ar_op));
        print_tree(prof); printf("Sender MAC : ");
        print_mac(arp_header->arp_sha);
        print_tree(prof); printf("Sender IP : %i.%i.%i.%i\n", arp_header->arp_spa[0],
                arp_header->arp_spa[1], arp_header->arp_spa[2], arp_header->arp_spa[3]);
        print_tree(prof); printf("Target MAC : ");
        print_mac(arp_header->arp_tha);
        print_tree(prof); printf("Target IP : %i.%i.%i.%i\n", arp_header->arp_tpa[0],
                arp_header->arp_tpa[1], arp_header->arp_tpa[2], arp_header->arp_tpa[3]);
        
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
        print_ipv6(ip->ip6_src);
        
        print_tree(prof); printf("IP dest  : ");
        print_ipv6(ip->ip6_src);
        break;
    case 3:
        print_new_state(prof); printf("IPV6 :\n");
        print_tree(prof); printf("IP source  : ");
        print_ipv6(ip->ip6_src); printf("\n");
        
        print_tree(prof); printf("IP dest  : ");
        print_ipv6(ip->ip6_src); printf("\n");
        
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
    struct udphdr *udp = (struct udphdr *)(packet);
    switch (verbose) {
    case 1:
        print_new_state(prof); printf("UDP \n");
        break;
    case 2:
        print_new_state(prof); printf("UDP :\n");
        print_tree(prof); printf("Port Source -> Destination : %d -> %d\n", 
                ntohs(udp->uh_sport), ntohs(udp->uh_dport));
        break;
    case 3:
        print_new_state(prof); printf("UDP :\n");
        print_tree(prof); printf("Port Source: %d\n", ntohs(udp->uh_sport));
        print_tree(prof); printf("Port Destination: %d\n", ntohs(udp->uh_dport));
        print_tree(prof); printf("Length : %i\n", ntohs(udp->uh_ulen));
        print_tree(prof); printf("Checksum : 0x%x\n", ntohs(udp->uh_sum));
        break;
    }

    // Rest of the packet (protocol under UDP)
    switch (ntohs(udp->uh_dport)) {
    case 0x43:
        parse_bootp(packet + sizeof(struct udphdr), verbose, prof +1);
        break;
    case 0x44:
        parse_dhcp(packet + sizeof(struct udphdr), verbose, prof +1);
        break;
    case 0x35:
        parse_dns(packet + sizeof(struct udphdr), verbose, prof +1);
        break;
    }
}

void parse_tcp(const u_char *packet, int verbose, int prof, int size){
    struct tcphdr *tcp = (struct tcphdr *)(packet);
    switch (verbose) {
    case 1:
        print_new_state(prof); printf("TCP \n");
        break;
    case 2:
        print_new_state(prof); printf("TCP :\n");
        print_tree(prof); printf("Port Source -> Destination : %d -> %d\n", ntohs(tcp->th_sport),
               ntohs(tcp->th_dport));
        break;
    case 3:
        print_new_state(prof); printf("TCP :\n");
        print_tree(prof); printf("Port Source: %d\n", ntohs(tcp->th_sport));
        print_tree(prof); printf("Port Destination: %d\n", ntohs(tcp->th_dport));
        print_tree(prof); printf("Sequence number : 0x%.2x (%u)\n", tcp->th_seq,
               ntohl(tcp->th_seq));
        print_tree(prof); printf("Acknowledgement number : 0x%.2x (%u)\n", tcp->th_ack,
               ntohl(tcp->th_ack));
        print_tree(prof);printf("Data offset : %i\n", tcp->th_off);
        print_tree(prof);printf("Flags : 0x%.2x ", tcp->th_flags); 
        //TAGS for the user's lisibility
        if (tcp->th_flags & TH_FIN) printf("FIN ");
        if (tcp->th_flags & TH_SYN) printf("SYN ");
        if (tcp->th_flags & TH_RST) printf("RST ");
        if (tcp->th_flags & TH_PUSH) printf("PUSH ");
        if (tcp->th_flags & TH_ACK) printf("ACK ");
        if (tcp->th_flags & TH_URG) printf("URG ");
        printf("\n");

        print_tree(prof); printf("Window : %u\n", ntohs(tcp->th_win));
        print_tree(prof); printf("Checksum : 0x%x\n", ntohs(tcp->th_sum));
        print_tree(prof); printf("Urgent Pointer : %.2x\n", tcp->th_urp);
        break;
    }
    // Rest of the packet (protocol under TCP)
    switch (ntohs(tcp->th_dport)) {
    case 0x50:
        parse_http(packet + sizeof(struct tcphdr), verbose, prof +1);
        break;
    case 0x15:  
        parse_ftp(packet + sizeof(struct tcphdr), verbose, prof +1);
        break;
    case 0x19:
        parse_smtp(packet + sizeof(struct tcphdr), verbose, prof +1);
        break;
    }

}

void parse_icmp(const u_char *packet, int verbose, int prof) {
    struct icmp *icmp = (struct icmp *)(packet);
    switch (verbose) {
    case 1:
        print_new_state(prof); printf("ICMP \n");
        break;
    case 2:
        print_new_state(prof); printf("ICMP :\n");
        print_tree(prof); printf("Type : %i\n", icmp->icmp_type);
        print_tree(prof); printf("Code : %i\n", icmp->icmp_code);
        break;
    case 3:
        print_new_state(prof); printf("ICMP :\n");
        print_tree(prof); printf("Type : %i\n", icmp->icmp_type);
        print_tree(prof); printf("Code : %i\n", icmp->icmp_code);
        print_tree(prof); printf("Checksum : 0x%x\n", ntohs(icmp->icmp_cksum));
        break;
    }
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

