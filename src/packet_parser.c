#include <stdio.h>
#include "packet_parser.h"
#include "tool.h"

void parse_ethernet(const u_char *packet, int verbose, int prof) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    switch(verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "ETHERNET");

       if(verbose == 1) break ; // No need to print the MACs

        PRINT_TREE(prof, "MAC Source : ");
        print_mac(eth_header->ether_shost); printf("\n");
        PRINT_TREE(prof, "MAC Destination : ");
        print_mac(eth_header->ether_dhost); printf("\n");

       if(verbose == 2) break ; // No need to print the type

        PRINT_TREE(prof, "type : %#2x \n", ntohs(eth_header->ether_type));
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
    case 2: 
    case 3:
        PRINT_NEW_STATE(prof, verbose, "ARP");

       if(verbose == 1) break ; // No need to print the MACs

        PRINT_TREE(prof, "MAC Source : ");
        print_mac(arp_header->arp_sha); printf("\n");
        PRINT_TREE(prof, "MAC Destination : ");
        print_mac(arp_header->arp_tha); printf("\n");

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Hardware type : %i", ntohs(arp_header->ea_hdr.ar_hrd));
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

        PRINT_TREE(prof, "Protocol type : %i", ntohs(arp_header->ea_hdr.ar_pro));
        //TAG for the user's lisibility
        switch (ntohs(arp_header->ea_hdr.ar_pro)) {
        case ETHERTYPE_IP: // 0x0800
            printf(" (IP)\n");
            break;
        case ETHERTYPE_IPV6: // 0x08dd
            printf(" (IPv6)\n");
            break;
        default:
            printf("(OTHER THAN IP)\n");
            break;
        }

        PRINT_TREE(prof, "Hardware size : %i\n", arp_header->ea_hdr.ar_hln);
        PRINT_TREE(prof, "Protocol size : %i\n", arp_header->ea_hdr.ar_pln);
        PRINT_TREE(prof, "Opcode : %i\n", ntohs(arp_header->ea_hdr.ar_op));
        PRINT_TREE(prof, "Sender MAC : ");
        print_mac(arp_header->arp_sha); printf("\n");
        PRINT_TREE(prof, "Sender IP : %i.%i.%i.%i\n", arp_header->arp_spa[0],
            arp_header->arp_spa[1], arp_header->arp_spa[2], arp_header->arp_spa[3]);
        PRINT_TREE(prof, "Target MAC : ");
        print_mac(arp_header->arp_tha); printf("\n");
        PRINT_TREE(prof, "Target IP : %i.%i.%i.%i\n", arp_header->arp_tpa[0],
                arp_header->arp_tpa[1], arp_header->arp_tpa[2], arp_header->arp_tpa[3]);
        
        break;
    }
}


void parse_ipv4(const u_char *packet, int verbose, int prof) {
    struct ip *ip = (struct ip *)(packet);

    switch(verbose) {
    case 1:
    case 2:    
    case 3:
        PRINT_NEW_STATE(prof, verbose, "IPV4");

       if(verbose == 1) break ; // No need to print the IP addresses

        PRINT_TREE(prof, "IP source : %s\n", inet_ntoa(ip->ip_src));
        PRINT_TREE(prof, "IP dest : %s\n", inet_ntoa(ip->ip_dst));

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "IP version : %i\n", ip->ip_v);
        PRINT_TREE(prof, "IP header length : %i (%i bytes)\n", 
                                    ip->ip_hl, ip->ip_hl * 4);
        PRINT_TREE(prof, "Type of Service : %i\n", ip->ip_tos);
        PRINT_TREE(prof, "Total length : %u\n", ntohs(ip->ip_len));
        PRINT_TREE(prof, "Transaction id : 0x%.2x\n",
                                    ntohs(ip->ip_id));
        PRINT_TREE(prof, "Fragment offset field : 0x%.2x\n", 
                                    ntohs(ip->ip_off));
        PRINT_TREE(prof, "Checksum : 0x%x\n", ntohs(ip->ip_sum));
        PRINT_TREE(prof, "Time to live : %i\n", ip->ip_ttl);
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
        parse_icmp(packet + (ip->ip_hl * 4), verbose, prof +1);
        break;
    }
}

void parse_ipv6(const u_char *packet, int verbose, int prof) {
    struct ip6_hdr *ip = (struct ip6_hdr *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "IPV6");

       if(verbose == 1) break ; // No need to print the IP addresses

        PRINT_TREE(prof, "IP source  : ");
        print_ipv6(ip->ip6_src); printf("\n");
        
        PRINT_TREE(prof, "IP dest  : ");
        print_ipv6(ip->ip6_src); printf("\n");
        
       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Flow : %.2x\n", ip->ip6_flow >> 8);
        PRINT_TREE(prof, "Payload Length : %u\n", ntohs(ip->ip6_plen));
        PRINT_TREE(prof, "Next header : 0x%x\n", ip->ip6_nxt);
        PRINT_TREE(prof, "Hop limit : %u\n", ip->ip6_hlim);
        PRINT_TREE(prof, "Version : %u\n", ip->ip6_vfc >> 4);
        PRINT_TREE(prof, "Traffic class : 0x%.2x\n", ip->ip6_flow >> 8);
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
        PRINT_NEW_STATE(prof, verbose, "ICMPv6");
        break;
    }
}

void parse_udp(const u_char *packet, int verbose, int prof, int size) {
    struct udphdr *udp = (struct udphdr *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "UDP");

       if(verbose == 1) break ; // No need to print the ports

        PRINT_TREE(prof, "Port Source: %d\n", ntohs(udp->uh_sport));
        PRINT_TREE(prof, "Port Destination: %d\n", ntohs(udp->uh_dport));

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Length : %i\n", ntohs(udp->uh_ulen));
        PRINT_TREE(prof, "Checksum : 0x%x\n", ntohs(udp->uh_sum));
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
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "TCP");

       if(verbose == 1) break ; // No need to print the ports

        PRINT_TREE(prof, "Port Source: %d\n", ntohs(tcp->th_sport));
        PRINT_TREE(prof, "Port Destination: %d\n", ntohs(tcp->th_dport));

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Sequence number : 0x%.2x (%u)\n", tcp->th_seq,
               ntohl(tcp->th_seq));
        PRINT_TREE(prof, "Acknowledgement number : 0x%.2x (%u)\n", tcp->th_ack,
               ntohl(tcp->th_ack));
        PRINT_TREE(prof, "Data offset : %i (%i bytes)\n", tcp->th_off, tcp->th_off * 4);
        PRINT_TREE(prof, "Flags : 0x%.2x", tcp->th_flags);
        //TAGS for the user's lisibility
        if (tcp->th_flags & TH_FIN) printf("FIN ");
        if (tcp->th_flags & TH_SYN) printf("SYN ");
        if (tcp->th_flags & TH_RST) printf("RST ");
        if (tcp->th_flags & TH_PUSH) printf("PUSH ");
        if (tcp->th_flags & TH_ACK) printf("ACK ");
        if (tcp->th_flags & TH_URG) printf("URG ");
        printf("\n");

        PRINT_TREE(prof, "Window : %u\n", ntohs(tcp->th_win));
        PRINT_TREE(prof, "Checksum : 0x%x\n", ntohs(tcp->th_sum));
        PRINT_TREE(prof, "Urgent Pointer : %.2x\n", tcp->th_urp);
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
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "ICMP");

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Type : %i\n", icmp->icmp_type);

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Code : %i\n", icmp->icmp_code);
        PRINT_TREE(prof, "Checksum : 0x%x\n", ntohs(icmp->icmp_cksum));
        break;
    }
}

void parse_bootp(const u_char *packet, int verbose, int prof) {
    struct bootp_header *bootp_header = (struct bootp_header *)(packet + sizeof(struct udphdr));

    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "BOOTP");

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Operation : %i\n", bootp_header->op);

        if(verbose == 2) break ; // No need to print the rest of the header
        
        PRINT_TREE(prof, "Hardware type : %i\n", bootp_header->htype);
        PRINT_TREE(prof, "Hardware address length : %i\n", bootp_header->hlen);
        PRINT_TREE(prof, "Hops : %i\n", bootp_header->hops);
        PRINT_TREE(prof, "Transaction ID : 0x%.2x\n", bootp_header->xid);
        PRINT_TREE(prof, "Seconds : %i\n", bootp_header->secs);
        PRINT_TREE(prof, "Flags : 0x%.2x\n", bootp_header->flags);
        PRINT_TREE(prof, "Client IP : %i.%i.%i.%i\n", bootp_header->ciaddr[0],
            bootp_header->ciaddr[1], bootp_header->ciaddr[2], bootp_header->ciaddr[3]);
        PRINT_TREE(prof, "Your IP : %i.%i.%i.%i\n", bootp_header->yiaddr[0],
            bootp_header->yiaddr[1], bootp_header->yiaddr[2], bootp_header->yiaddr[3]);
        PRINT_TREE(prof, "Server IP : %i.%i.%i.%i\n", bootp_header->siaddr[0],
            bootp_header->siaddr[1], bootp_header->siaddr[2], bootp_header->siaddr[3]);
        PRINT_TREE(prof, "Gateway IP : %i.%i.%i.%i\n", bootp_header->giaddr[0],
            bootp_header->giaddr[1], bootp_header->giaddr[2], bootp_header->giaddr[3]);
        PRINT_TREE(prof, "Client hardware address : ");
        print_mac(bootp_header->chaddr); printf("\n");
        PRINT_TREE(prof, "Server host name : %s\n", bootp_header->sname);
        PRINT_TREE(prof, "Boot file name : %s\n", bootp_header->file);
        PRINT_TREE(prof, "Magic cookie : 0x%.2x\n", bootp_header->magic);
        break;
    }  
}

void parse_dhcp(const u_char *packet, int verbose, int prof) {
    struct dhcp_header *dhcp_header = (struct dhcp_header *)(packet + sizeof(struct iphdr));
    
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "DHCP");

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Operation : %i\n", dhcp_header->op);

        if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Hardware type : %i\n", dhcp_header->htype);
        PRINT_TREE(prof, "Hardware address length : %i\n", dhcp_header->hlen);
        PRINT_TREE(prof, "Hops : %i\n", dhcp_header->hops);
        PRINT_TREE(prof, "Transaction ID : 0x%.2x\n", dhcp_header->xid);
        PRINT_TREE(prof, "Seconds : %i\n", dhcp_header->secs);
        PRINT_TREE(prof, "Flags : 0x%.2x\n", dhcp_header->flags);
        PRINT_TREE(prof, "Client IP : %i.%i.%i.%i\n", dhcp_header->ciaddr[0],
            dhcp_header->ciaddr[1], dhcp_header->ciaddr[2], dhcp_header->ciaddr[3]);
        PRINT_TREE(prof, "Your IP : %i.%i.%i.%i\n", dhcp_header->yiaddr[0],
            dhcp_header->yiaddr[1], dhcp_header->yiaddr[2], dhcp_header->yiaddr[3]);
        PRINT_TREE(prof, "Server IP : %i.%i.%i.%i\n", dhcp_header->siaddr[0],
            dhcp_header->siaddr[1], dhcp_header->siaddr[2], dhcp_header->siaddr[3]);
        PRINT_TREE(prof, "Gateway IP : %i.%i.%i.%i\n", dhcp_header->giaddr[0],
            dhcp_header->giaddr[1], dhcp_header->giaddr[2], dhcp_header->giaddr[3]);
        PRINT_TREE(prof, "Client hardware address : ");
        print_mac(dhcp_header->chaddr); printf("\n");
        PRINT_TREE(prof, "Server host name : %s\n", dhcp_header->sname);
        PRINT_TREE(prof, "Boot file name : %s\n", dhcp_header->file);
        PRINT_TREE(prof, "Magic cookie : 0x%.2x\n", dhcp_header->magic);
        break;
    }
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

