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
        PRINT_TREE(prof, "Sender IP :" );
        print_ip_from_uint8(arp_header->arp_spa); printf("\n");
        PRINT_TREE(prof, "Target MAC : ");
        print_mac(arp_header->arp_tha); printf("\n");
        PRINT_TREE(prof, "Target IP :");
        print_ip_from_uint8(arp_header->arp_tpa); printf("\n");
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
        parse_bootp(packet + sizeof(struct udphdr), verbose, prof +1);
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

        PRINT_TREE(prof, "Code : %i", icmp->icmp_code);
        //TAG for the user's lisibility
        switch (icmp->icmp_code) {
        case ICMP_ECHOREPLY:
            printf(" (Echo Reply)\n");
            break;
        case ICMP_UNREACH:
            printf(" (Destination Unreachable)\n");
            break;
        case ICMP_SOURCEQUENCH:
            printf(" (Source Quench)\n");
            break;
        case ICMP_REDIRECT:
            printf(" (Redirect (change route))\n");
            break;
        case ICMP_ECHO:
            printf(" (Echo Request)\n");
            break;
        case ICMP_TIMXCEED:
            printf(" (Time Exceeded)\n");
            break;
        case ICMP_PARAMPROB:
            printf(" (Parameter Problem)\n");
            break;  

        default:
            printf(" (Unknown)\n");
            break;
        }
        PRINT_TREE(prof, "Checksum : 0x%x\n", ntohs(icmp->icmp_cksum));
        break;
    }
}

void parse_bootp(const u_char *packet, int verbose, int prof) {
    struct bootp *bootp_header = (struct bootp *)(packet);

    switch (verbose) {
    case 1:
    case 2:
    case 3:
        switch (dhcp_tag(bootp_header))
        {
        case DHCPDISCOVER:
            PRINT_NEW_STATE(prof, verbose, "DHCP (DISCOVER)");
            break;

        case DHCPOFFER:
            PRINT_NEW_STATE(prof, verbose, "DHCP (OFFER)");
            break;

        case DHCPREQUEST:
            PRINT_NEW_STATE(prof, verbose, "DHCP (REQUEST)");
            break;
        
        case DHCPDECLINE:
            PRINT_NEW_STATE(prof, verbose, "DHCP (DECLINE)");
            break;

        case DHCPACK:
            PRINT_NEW_STATE(prof, verbose, "DHCP (ACK)");
            break;

        case DHCPNAK:
            PRINT_NEW_STATE(prof, verbose, "DHCP (NAK)");
            break;

        case DHCPRELEASE:
            PRINT_NEW_STATE(prof, verbose, "DHCP (RELEASE)");
            break;

        case DHCPINFORM:
            PRINT_NEW_STATE(prof, verbose, "DHCP (INFORM)");
            break;

        default:
            PRINT_NEW_STATE(prof, verbose, "BOOTP");
            break;
        } 

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Operation : %i", bootp_header->bp_op);
        //TAG for the user's lisibility
        switch (bootp_header->bp_op) {
        case BOOTREQUEST:
            printf(" (Request)\n");
            break;
        case BOOTREPLY:
            printf(" (Reply)\n");
            break;
        default:
            printf(" (Unknown)\n");
            break;
        }

         if(verbose == 2) break ; // No need to print the rest of the header    

        PRINT_TREE(prof, "Hardware type : %i\n", bootp_header->bp_htype);
        PRINT_TREE(prof, "Hardware address length : %i\n", bootp_header->bp_hlen);
        PRINT_TREE(prof, "Hops : %i\n", bootp_header->bp_hops);
        PRINT_TREE(prof, "Transaction ID : 0x%.2x\n", bootp_header->bp_xid);
        PRINT_TREE(prof, "Seconds : %i\n", bootp_header->bp_secs);
        PRINT_TREE(prof, "Flags : 0x%.2x\n", bootp_header->bp_flags);
        PRINT_TREE(prof, "Client IP : ");

        print_ip(bootp_header->bp_ciaddr); printf("\n");
        PRINT_TREE(prof, "Your IP : ");
        print_ip(bootp_header->bp_yiaddr); printf("\n");
        PRINT_TREE(prof, "Server IP : ");
        print_ip(bootp_header->bp_siaddr); printf("\n");
        PRINT_TREE(prof, "Gateway IP : ");
        print_ip(bootp_header->bp_giaddr); printf("\n");
        PRINT_TREE(prof, "Client hardware address : ");
        print_mac(bootp_header->bp_chaddr); printf("\n");

        PRINT_TREE(prof, "Server host name : %s\n", bootp_header->bp_sname);
        PRINT_TREE(prof, "Boot file name : %s\n", bootp_header->bp_file);
        PRINT_TREE(prof, "Magic cookie : 0x%.2x\n", bootp_header->bp_vend);

        //Option parsing
        int i = 4 ;
        while (i < 64) {
            switch (bootp_header->bp_vend[i]) {
            case TAG_PAD:
                i++;
                break;
            case TAG_SUBNET_MASK:
                PRINT_TREE(prof, "Subnet mask : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_TIME_OFFSET:
                PRINT_TREE(prof, "Time offset : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_GATEWAY:
                PRINT_TREE(prof, "Gateway : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_TIME_SERVER:
                PRINT_TREE(prof, "Time server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_NAME_SERVER:
                PRINT_TREE(prof, "Name server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_DOMAIN_SERVER:
                PRINT_TREE(prof, "Domain server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_LOG_SERVER:
                PRINT_TREE(prof, "Log server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            case TAG_COOKIE_SERVER:
                PRINT_TREE(prof, "Cookie server : ");
                print_ip_from_uint8(bootp_header);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
            
            case TAG_LPR_SERVER:
                PRINT_TREE(prof, "LPR server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
            
            case TAG_IMPRESS_SERVER:
                PRINT_TREE(prof, "Impress server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;

            case TAG_RLP_SERVER:
                PRINT_TREE(prof, "RLP server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;

            case TAG_HOSTNAME:
                PRINT_TREE(prof, "Hostname : %s\n", bootp_header->bp_vend + i + 2);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_BOOTSIZE:
                PRINT_TREE(prof, "Bootsize : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case  TAG_REQUESTED_IP:
                PRINT_TREE(prof, "Requested IP : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_IP_LEASE:
                PRINT_TREE(prof, "Lease time : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_OPT_OVERLOAD:
                PRINT_TREE(prof, "Overload : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_DHCP_MESSAGE:
                PRINT_TREE(prof, "DHCP message : %i", bootp_header->bp_vend[i + 2]);
                //TAG for the user's lisibility
                switch (bootp_header->bp_vend[i + 2]) {
                case DHCPDISCOVER:
                    printf(" (Discover)\n");
                    break;
                case DHCPOFFER:
                    printf(" (Offer)\n");
                    break;
                case DHCPREQUEST:
                    printf(" (Request)\n");
                    break;
                case DHCPDECLINE:   
                    printf(" (Decline)\n");
                    break;
                case DHCPACK:
                    printf(" (ACK)\n");
                    break;
                case DHCPNAK:
                    printf(" (NAK)\n");
                    break;
                case DHCPRELEASE:
                    printf(" (Release)\n");
                    break;
                case DHCPINFORM:
                    printf(" (Inform)\n");
                    break;
                default:
                    printf(" (Unknown)\n");
                    break;
                }
                
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_SERVER_ID:
                PRINT_TREE(prof, "DHCP server : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_PARM_REQUEST:
                PRINT_TREE(prof, "Parameter request : ");
                for (int j = 0; j < bootp_header->bp_vend[i + 1]; j++) {
                    printf("%i ", bootp_header->bp_vend[i + 2 + j]);
                }
                printf("\n");
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_MESSAGE:
                PRINT_TREE(prof, "Message : %s\n", bootp_header->bp_vend + i + 2);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_MAX_MSG_SIZE:
                PRINT_TREE(prof, "Max size : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_RENEWAL_TIME:
                PRINT_TREE(prof, "Renewal time : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_REBIND_TIME:
                PRINT_TREE(prof, "Rebind time : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_VENDOR_CLASS:
                PRINT_TREE(prof, "Vendor class : %s\n", bootp_header->bp_vend + i + 2);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            
            case TAG_CLIENT_ID:
                PRINT_TREE(prof, "Client ID : %i\n", bootp_header->bp_vend[i + 2]);
                i += bootp_header->bp_vend[i + 1] + 2;
                break;

            case TAG_END:
                i = 64;
                break;
            
            default:
                i += bootp_header->bp_vend[i + 1] + 2;
                break;
            }
        }
        break;
    }  
}

int dhcp_tag(struct bootp* bootp_header){
    int i = 4;
    while (i < 64) {
        switch (bootp_header->bp_vend[i]) {
        case TAG_DHCP_MESSAGE:
            return bootp_header->bp_vend[i + 2];
            break;
        default:
            i += bootp_header->bp_vend[i + 1] + 2;
            break;
        }
    }
    return 0;
}

void parse_dns(const u_char *packet, int verbose, int prof) {
    struct dns_header *dns_header = (struct dns_header *)(packet + sizeof(struct iphdr));
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "DNS");

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Transaction ID : 0x%.2x\n", ntohs(dns_header->id));
        PRINT_TREE(prof, "Flags : 0x%.2x", ntohs(dns_header->flags));
        //TAG for the user's lisibility
        if (ntohs(dns_header->flags) & DNS_QR) printf("QR ");
        if (ntohs(dns_header->flags) & DNS_OPCODE) printf("OPCODE ");
        if (ntohs(dns_header->flags) & DNS_AA) printf("AA ");
        if (ntohs(dns_header->flags) & DNS_TC) printf("TC ");
        if (ntohs(dns_header->flags) & DNS_RD) printf("RD ");
        if (ntohs(dns_header->flags) & DNS_RA) printf("RA ");
        if (ntohs(dns_header->flags) & DNS_Z) printf("Z ");
        if (ntohs(dns_header->flags) & DNS_RCODE) printf("RCODE ");
        printf("\n");

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Questions : %i\n", ntohs(dns_header->qdcount));
        PRINT_TREE(prof, "Answer RRs : %i\n", ntohs(dns_header->ancount));
        PRINT_TREE(prof, "Authority RRs : %i\n", ntohs(dns_header->nscount));
        PRINT_TREE(prof, "Additional RRs : %i\n", ntohs(dns_header->arcount));
        break;
    }
}

void parse_http(const u_char *packet, int verbose, int prof) {
    struct http_header *http_header = (struct http_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, "HTTP");

        if(verbose >= 2) PRINT_TREE(prof, "Method : %s", http_header->method);
        //TAG for the user's lisibility
        if (strcmp(http_header->method, "GET") == 0) printf(" (GET)\n");
        else if (strcmp(http_header->method, "POST") == 0) printf(" (POST)\n");
        else if (strcmp(http_header->method, "HEAD") == 0) printf(" (HEAD)\n");
        else if (strcmp(http_header->method, "PUT") == 0) printf(" (PUT)\n");
        else if (strcmp(http_header->method, "DELETE") == 0) printf(" (DELETE)\n");
        else if (strcmp(http_header->method, "CONNECT") == 0) printf(" (CONNECT)\n");
        else if (strcmp(http_header->method, "OPTIONS") == 0) printf(" (OPTIONS)\n");
        else if (strcmp(http_header->method, "TRACE") == 0) printf(" (TRACE)\n");
        else if (strcmp(http_header->method, "PATCH") == 0) printf(" (PATCH)\n");
        else printf(" (Unknown)\n");

        if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "URI : %s\n", http_header->uri);
        PRINT_TREE(prof, "Version : %s\n", http_header->version);

        if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Status code : %i\n", http_header->status_code);
        PRINT_TREE(prof, "Reason phrase : %s\n", http_header->reason_phrase);
        PRINT_TREE(prof, "Headers : %s\n", http_header->headers);
        PRINT_TREE(prof, "Body : %s\n", http_header->body);
        break;
    }
}

void parse_ftp(const u_char *packet, int verbose, int prof) {
    struct ftp_header *ftp_header = (struct ftp_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete FTP ici
}

void parse_smtp(const u_char *packet, int verbose, int prof) {
    struct smtp_header *smtp_header = (struct smtp_header *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
    // Traitement de l'en-tete SMTP ici
}

