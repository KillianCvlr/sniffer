#include "packet_parser.h"


void parse_ethernet(const u_char *packet, int verbose, int prof) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    switch(verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BHMAG "ETHERNET" MAG);

       if(verbose == 1) break ; // No need to print the MACs

        PRINT_TREE(prof, BMAG "MAC Source : " MAG);
        print_mac(eth_header->ether_shost); printf("\n");
        PRINT_TREE(prof, BMAG "MAC Destination : " MAG);
        print_mac(eth_header->ether_dhost); printf("\n");

       if(verbose == 2) break ; // No need to print the type

        PRINT_TREE(prof, BMAG "Type :" MAG " %#2x \n", ntohs(eth_header->ether_type));
        break;
    }

    // Rest of the packet (protocol under Ethernet)
    printf(BLU);
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
        PRINT_NEW_STATE(prof, verbose, BHBLU "ARP" BLU);

       if(verbose == 1) break ; // No need to print the MACs

        PRINT_TREE(prof, BBLU "MAC Source : " BLU);
        print_mac(arp_header->arp_sha); printf("\n");
        PRINT_TREE(prof, BBLU "MAC Destination : " BLU);
        print_mac(arp_header->arp_tha); printf("\n");

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BBLU "Hardware type : " BLU "%i", ntohs(arp_header->ea_hdr.ar_hrd));
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

        PRINT_TREE(prof, BBLU "Protocol type : " BLU "%i", ntohs(arp_header->ea_hdr.ar_pro));
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

        PRINT_TREE(prof, BBLU "Hardware size : " BLU "%i\n", arp_header->ea_hdr.ar_hln);
        PRINT_TREE(prof, BBLU "Protocol size : " BLU "%i\n", arp_header->ea_hdr.ar_pln);
        PRINT_TREE(prof, BBLU "Opcode : " BLU "%i\n", ntohs(arp_header->ea_hdr.ar_op));
        PRINT_TREE(prof, BBLU "Sender MAC : " BLU);
        print_mac(arp_header->arp_sha); printf("\n");
        PRINT_TREE(prof, BBLU "Sender IP :" BLU);
        print_ip_from_uint8(arp_header->arp_spa); printf("\n");
        PRINT_TREE(prof, BBLU "Target MAC : " BLU);
        print_mac(arp_header->arp_tha); printf("\n");
        PRINT_TREE(prof, BBLU "Target IP :" BLU);
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
        PRINT_NEW_STATE(prof, verbose, BBLU "IPV4" BLU);

       if(verbose == 1) break ; // No need to print the IP addresses

        PRINT_TREE(prof, BBLU "IP source : " BLU "%s\n", inet_ntoa(ip->ip_src));
        PRINT_TREE(prof, BBLU "IP dest : " BLU "%s\n", inet_ntoa(ip->ip_dst));

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BBLU "IP version  :" BLU" %i\n", ip->ip_v);
        PRINT_TREE(prof, BBLU "IP header length  :" BLU" %i (%i bytes)\n", 
                                    ip->ip_hl, ip->ip_hl * 4);
        PRINT_TREE(prof, BBLU "Type of Service  :" BLU" %i\n", ip->ip_tos);
        PRINT_TREE(prof, BBLU "Total length  :" BLU" %u\n", ntohs(ip->ip_len));
        PRINT_TREE(prof, BBLU "Transaction id  :" BLU" 0x%.2x\n",
                                    ntohs(ip->ip_id));
        PRINT_TREE(prof, BBLU "Fragment offset field  :" BLU" 0x%.2x\n", 
                                    ntohs(ip->ip_off));
        PRINT_TREE(prof, BBLU "Checksum  :" BLU" 0x%x\n", ntohs(ip->ip_sum));
        PRINT_TREE(prof, BBLU "Time to live  :" BLU" %i\n", ip->ip_ttl);
        break;
    }
    printf(CYN);
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
        PRINT_NEW_STATE(prof, verbose, BBLU "IPV6" BLU);

       if(verbose == 1) break ; // No need to print the IP addresses

        PRINT_TREE(prof, BBLU "IP source  :" BLU " ");
        print_ipv6(ip->ip6_src); printf("\n");
        
        PRINT_TREE(prof, BBLU "IP dest  :" BLU " ");
        print_ipv6(ip->ip6_src); printf("\n");
        
       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BBLU "Flow :" BLU " %.2x\n", ip->ip6_flow >> 8);
        PRINT_TREE(prof, BBLU "Payload Length :" BLU " %u\n", ntohs(ip->ip6_plen));
        PRINT_TREE(prof, BBLU "Next header :" BLU " 0x%x\n", ip->ip6_nxt);
        PRINT_TREE(prof, BBLU "Hop limit :" BLU " %u\n", ip->ip6_hlim);
        PRINT_TREE(prof, BBLU "Version :" BLU " %u\n", ip->ip6_vfc >> 4);
        PRINT_TREE(prof, BBLU "Traffic class :" BLU " 0x%.2x\n", ip->ip6_flow >> 8);
        break;
    }
    int size = ntohs(ip->ip6_plen);
    printf(CYN);
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
        PRINT_NEW_STATE(prof, verbose, BCYN "UDP" CYN);

       if(verbose == 1) break ; // No need to print the ports

        PRINT_TREE(prof, BCYN "Port Source: " CYN " %d\n", ntohs(udp->uh_sport));
        PRINT_TREE(prof, BCYN "Port Destination: " CYN " %d\n", ntohs(udp->uh_dport));

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Length : " CYN " %i\n", ntohs(udp->uh_ulen));
        PRINT_TREE(prof, BCYN "Checksum : " CYN " 0x%x\n", ntohs(udp->uh_sum));
        break;
    }

    // Rest of the packet (protocol under UDP)
    printf(GRN);
    switch (ntohs(udp->uh_sport)) {
    case 0x43:
    case 0x44:
        parse_bootp(packet + sizeof(struct udphdr), verbose, prof +1);
        break;
    case 0x35:
        parse_dns(packet + sizeof(struct udphdr), verbose, prof +1);
        break;
    default:
        switch (ntohs(udp->uh_dport)) {
        case 0x43:
        case 0x44:
            parse_bootp(packet + sizeof(struct udphdr), verbose, prof +1);
            break;
        case 0x35:
            parse_dns(packet + sizeof(struct udphdr), verbose, prof +1);
            break;
        default:
            PRINT_NEW_STATE(prof +1, verbose, "DATA");
            break;
        }
        break;
    }
}

void parse_tcp(const u_char *packet, int verbose, int prof, int size){
    struct tcphdr *tcp = (struct tcphdr *)(packet);
    int continue_parsing = 0;
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BCYN "TCP " CYN);
            if(verbose == 1){
            if (tcp->th_flags & TH_FIN) printf("FIN ");
            if (tcp->th_flags & TH_SYN) printf("SYN ");
            if (tcp->th_flags & TH_RST) printf("RST ");
            if (tcp->th_flags & TH_PUSH) printf("PUSH ");
            if (tcp->th_flags & TH_ACK) printf("ACK ");
            if (tcp->th_flags & TH_URG) printf("URG ");
        }

       if(verbose == 1) break ; // No need to print the ports

        PRINT_TREE(prof, BCYN "Port Source: " CYN " %d\n", ntohs(tcp->th_sport));
        PRINT_TREE(prof, BCYN "Port Destination: " CYN " %d\n", ntohs(tcp->th_dport));
        PRINT_TREE(prof, BCYN "Flags : " CYN " 0x%.2x ", tcp->th_flags);

        //TAGS for the user's lisibility
        if (tcp->th_flags & TH_FIN) printf("FIN ");
        if (tcp->th_flags & TH_SYN) printf("SYN ");
        if (tcp->th_flags & TH_RST) printf("RST ");
        if (tcp->th_flags & TH_PUSH) printf("PUSH ");
        if (tcp->th_flags & TH_ACK) printf("ACK ");
        if (tcp->th_flags & TH_URG) printf("URG ");
        printf("\n");

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BCYN "Sequence number : " CYN " 0x%.2x (%u)\n", tcp->th_seq,
               ntohl(tcp->th_seq));
        PRINT_TREE(prof, BCYN "Acknowledgement number : " CYN " 0x%.2x (%u)\n", tcp->th_ack,
               ntohl(tcp->th_ack));
        PRINT_TREE(prof, BCYN "Data offset : " CYN " %i (%i bytes)\n", tcp->th_off, tcp->th_off * 4);
        

        PRINT_TREE(prof, BCYN "Window : " CYN " %u\n", ntohs(tcp->th_win));
        PRINT_TREE(prof, BCYN "Checksum : " CYN " 0x%x\n", ntohs(tcp->th_sum));
        PRINT_TREE(prof, BCYN "Urgent Pointer : " CYN " %.2x\n", tcp->th_urp);
        break;
    }
    // check if only used in order to flag the TCP protocol 
    //or used in an other protocol (flag PSH present)
    printf(GRN);
    size -= 4*tcp->th_off;
    if(size) {
        // Rest of the packet (protocol under TCP)
        switch (ntohs(tcp->th_sport)) {
        case 0x50:
            parse_http(packet + 4*tcp->th_off, verbose, prof +1, size );
            break;
        case 0x15:  
            parse_ftp(packet + 4*tcp->th_off, verbose, prof +1,  size);
            break;
        case 0x19:
        case 0x1D1:
        case 0x24B:
            parse_smtp(packet + 4*tcp->th_off, verbose, prof +1,  size);
            break;
        case 0x17:
            parse_telnet(packet + 4*tcp->th_off, verbose, prof +1, size);
            break;
        case 0x43:
        case 0x44:
            parse_bootp(packet + 4*tcp->th_off, verbose, prof +1);
            break;
        case 0x35:
            parse_dns(packet + 4*tcp->th_off, verbose, prof +1);
            break;
        case 0x8F:
            parse_imap(packet + 4*tcp->th_off, verbose, prof +1, size);
            break;
        case 0x6E:
            parse_pop3(packet + 4*tcp->th_off, verbose, prof +1, size);
            break;
        default:
            switch (ntohs(tcp->th_dport)) {
            case 0x50:
                parse_http(packet + 4*tcp->th_off, verbose, prof +1, size );
                break;
            case 0x15:  
                parse_ftp(packet + 4*tcp->th_off, verbose, prof +1,  size);
                break;
            case 0x19:
            case 0x1D1:
            case 0x24B:
                parse_smtp(packet + 4*tcp->th_off, verbose, prof +1,  size);
                break;
            case 0x17:
                parse_telnet(packet + 4*tcp->th_off, verbose, prof +1, size);
                break;
            case 0x43:
            case 0x44:
                parse_bootp(packet + 4*tcp->th_off, verbose, prof +1);
                break;
            case 0x35:
                parse_dns(packet + 4*tcp->th_off, verbose, prof +1);
                break;
            case 0x8F:
                parse_imap(packet + 4*tcp->th_off, verbose, prof +1, size);
                break;
            case 0x6E:
                parse_pop3(packet + 4*tcp->th_off, verbose, prof +1, size);
                break;
            default :
                PRINT_NEW_STATE(prof +1, verbose, "DATA");
                print_content(prof +1, verbose, size, packet + 4*tcp->th_off);
            }
        }
    }
}

void parse_icmp(const u_char *packet, int verbose, int prof) {
    struct icmp *icmp = (struct icmp *)(packet);
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "ICMP" GRN);

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BGRN "Type : " GRN " %i\n", icmp->icmp_type);

       if(verbose == 2) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BGRN "Code : " GRN " %i", icmp->icmp_code);
        //TAG for the user's lisibility
        switch (icmp->icmp_code) {
        case ICMP_ECHOREPLY:
            printf(" (Echo Reply)\n");
            break;
        case ICMP_DEST_UNREACH:
            printf(" (Destination Unreachable)\n");
            break;
        case ICMP_SOURCE_QUENCH:
            printf(" (Source Quench)\n");
            break;
        case ICMP_REDIRECT:
            printf(" (Redirect (change route))\n");
            break;
        case ICMP_ECHO:
            printf(" (Echo Request)\n");
            break;
        case ICMP_TIME_EXCEEDED:
            printf(" (Time Exceeded)\n");
            break;
        case ICMP_PARAMETERPROB:
            printf(" (Parameter Problem)\n");
            break;  

        default:
            printf(" (Unknown)\n");
            break;
        }
        PRINT_TREE(prof, BGRN "Checksum : " GRN "0x%x\n", ntohs(icmp->icmp_cksum));
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
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (DISCOVER)");
            break;

        case DHCPOFFER:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (OFFER)");
            break;

        case DHCPREQUEST:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (REQUEST)");
            break;
        
        case DHCPDECLINE:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (DECLINE)");
            break;

        case DHCPACK:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (ACK)");
            break;

        case DHCPNAK:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (NAK)");
            break;

        case DHCPRELEASE:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (RELEASE)");
            break;

        case DHCPINFORM:
            PRINT_NEW_STATE(prof, verbose, BGRN "DHCP" GRN " (INFORM)");
            break;

        default:
            PRINT_NEW_STATE(prof, verbose, BGRN "BOOTP" GRN "");
            break;
        } 

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, BGRN "Operation : " GRN " %i", bootp_header->bp_op);
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

        PRINT_TREE(prof, BGRN "Hardware type : " GRN " %i\n", bootp_header->bp_htype);
        PRINT_TREE(prof, BGRN "Hardware address length : " GRN " %i\n", bootp_header->bp_hlen);
        PRINT_TREE(prof, BGRN "Hops : " GRN " %i\n", bootp_header->bp_hops);
        PRINT_TREE(prof, BGRN "Transaction ID : " GRN " 0x%.2x\n", bootp_header->bp_xid);
        PRINT_TREE(prof, BGRN "Seconds : " GRN " %i\n", bootp_header->bp_secs);
        PRINT_TREE(prof, BGRN "Flags : " GRN " 0x%.2x\n", bootp_header->bp_flags);
        PRINT_TREE(prof, BGRN "Client IP : " GRN " ");

        print_ip(bootp_header->bp_ciaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Your IP : " GRN " ");
        print_ip(bootp_header->bp_yiaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Server IP : " GRN " ");
        print_ip(bootp_header->bp_siaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Gateway IP : " GRN " ");
        print_ip(bootp_header->bp_giaddr); printf("\n");
        PRINT_TREE(prof, BGRN "Client hardware address : " GRN " ");
        print_mac(bootp_header->bp_chaddr); printf("\n");

        PRINT_TREE(prof, BGRN "Server host name : " GRN " %s\n", bootp_header->bp_sname);
        PRINT_TREE(prof, BGRN "Boot file name : " GRN " %s\n", bootp_header->bp_file);
        if(dhcp_tag(bootp_header)){ 
            PRINT_TREE(prof, BGRN "Magic cookie : " GRN);
            printf("0x%.2x%.2x%.2x%.2x", bootp_header->bp_vend[0], 
                    bootp_header->bp_vend[1],
                    bootp_header->bp_vend[2], 
                    bootp_header->bp_vend[3] );
            printf("\n");
        }


        //Option parsing
        int i = 4 ;
        int size = 0;
        while (i < 64) {
            switch (bootp_header->bp_vend[i]) {
            case TAG_PAD:
                i++;
                break;
            case TAG_SUBNET_MASK:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Subnet mask : ");
                print_ip_from_uint8(bootp_header->bp_vend + i + 2); printf("   ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            case TAG_TIME_OFFSET:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Time offset : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                break;
            case TAG_GATEWAY:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Gateway : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_TIME_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Time server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_NAME_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Name server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_DOMAIN_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Domain server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_LOG_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Log server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            case TAG_COOKIE_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Cookie server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            
            case TAG_LPR_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "LPR server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;
            
            case TAG_IMPRESS_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Impress server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;
                break;

            case TAG_RLP_SERVER:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "RLP server : ");
                if (size / 4) {
                    printf("\n");
                    for(int nb = 0; nb < (size /4); nb++){
                        print_tree(prof); printf("\t");
                        print_ip_from_uint8(bootp_header->bp_vend + i + 2 + nb*4);
                        printf("   ");
                        print_dhcp_arg(4 , i + nb*4, bootp_header->bp_vend);
                    }
                } else {
                    print_ip_from_uint8(bootp_header->bp_vend + i + 2);
                    printf("   ");
                    print_dhcp_arg(size, i, bootp_header->bp_vend);
                }
                i += size + 2;

            case TAG_HOSTNAME:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Hostname : ");
                for(int j = 0; j < size; j++){
                    printf("%c", bootp_header->bp_vend[i + 2 + j]);
                }
                printf(" ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
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
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Lease time : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            
            case TAG_OPT_OVERLOAD:
                PRINT_TREE(prof, "Option overload : \n");
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
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "MESSAGE : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;

            case TAG_MAX_MSG_SIZE:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Max message size : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            
            case TAG_RENEWAL_TIME:
                int size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Renewal time : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;
            
            case TAG_REBIND_TIME:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Rebind time : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;

            case TAG_VENDOR_CLASS:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Vendor class : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                i += size + 2;
                break;

            case TAG_CLIENT_ID:
                size = bootp_header->bp_vend[i + 1];
                PRINT_TREE(prof, "Client ID : ");
                print_dhcp_arg(size, i, bootp_header->bp_vend);
                print_content(prof, verbose, size, bootp_header->bp_vend + i + 2);
                printf("\n");                
                print_tree(prof); printf("\n");
                i += size + 2;
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

print_dhcp_arg(int size, int i, u_int8_t *bp_vend){
    printf("0x");
    for(int j = 0; j < size; j++){
        printf("%.2x", bp_vend[i + 2 + j]);
    }
    printf("\n");
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
    struct dns_header *dns_header = (struct dns_header *)packet;
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "DNS" GRN);

       if(verbose == 1) break ; // No need to print the rest of the header

        PRINT_TREE(prof, "Transaction ID : 0x%.2x\n", ntohs(dns_header->id));
        PRINT_TREE(prof, "Flags : 0x%.2x ", ntohs(dns_header->flags));
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

        //TO DO : parse the rest of the packet ie questions, answers, authority, additional
    }
}

void parse_http(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:            
        if (strstr(packet, "GET") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (GET)");
        } else if (strstr(packet, "HEAD") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (HEAD)");
        } else if (strstr(packet, "POST") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (POST)");
        } else if (strstr(packet, "PUT") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (PUT)");
        } else if (strstr(packet, "DELETE") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (DELETE)");
        } else if (strstr(packet, "CONNECT") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (CONNECT)");
        } else if (strstr(packet, "OPTIONS") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (OPTIONS)");
        } else if (strstr(packet, "TRACE") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (TRACE)");
        } else if (strstr(packet, "PATCH") != NULL) {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (PATCH)");
        } else if (strstr(packet, "OK") != NULL){
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " (OK)");
        } else {
            PRINT_NEW_STATE(prof, verbose, BGRN "HTTP" GRN " ()");
        }

        if(verbose == 1) break ; // No need to print the rest of the header

        if(verbose == 2) break ; // No need to print the rest of the header

        print_content(prof, verbose, size, packet);

        break;
    }
}

void parse_ftp(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "FTP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header

        // FTP is pretty-much self-explanatory, no need to parse the options
        print_content(prof, verbose, size, packet);
    }

}

void parse_smtp(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "SMTP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        print_content(prof, verbose, size, packet);
    }
}

void parse_imap(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "IMAP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        print_content(prof, verbose, size, packet);
    }
}
void parse_telnet(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "TELNET" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        if(size){
            if (packet[0] == TELNET_IAC) {
                PRINT_TREE(prof, "IAC \n");
                switch (packet[1]) {
                case TELNET_WILL:
                    PRINT_TREE(prof, "WILL \n");
                    break;
                case TELNET_WONT:
                    PRINT_TREE(prof, "WONT \n");
                    break;
                case TELNET_DO:
                    PRINT_TREE(prof, "DO \n");
                    break;
                case TELNET_DONT:
                    PRINT_TREE(prof, "DONT \n");
                    break;
                case TELNET_SB:
                    PRINT_TREE(prof, "SB \n");
                    break;
                case TELNET_GA:
                    PRINT_TREE(prof, "GA \n");
                    break;
                case TELNET_EL:
                    PRINT_TREE(prof, "EL \n");
                    break;
                case TELNET_EC:
                    PRINT_TREE(prof, "EC \n");
                    break;
                case TELNET_AYT:
                    PRINT_TREE(prof, "AYT \n");
                    break;
                case TELNET_AO:
                    PRINT_TREE(prof, "AO \n");
                    break;
                case TELNET_IP:
                    PRINT_TREE(prof, "IP \n");
                    break;
                case TELNET_BREAK:
                    PRINT_TREE(prof, "BREAK \n");
                    break;
                case TELNET_DM:
                    PRINT_TREE(prof, "DM \n");
                    break;
                case TELNET_NOP:
                    PRINT_TREE(prof, "NOP \n");
                    break;
                case TELNET_SE:
                    PRINT_TREE(prof, "SE \n");
                    break;
                default:
                    PRINT_TREE(prof, "UNKNOWN \n");
                    break;
                }
                switch (packet[2]) {
                case TELNET_BINARY:
                    PRINT_TREE(prof, "BINARY \n");
                    break;
                case TELNET_ECHO:
                    PRINT_TREE(prof, "ECHO \n");
                    break;
                case TELNET_RECONNECTION:
                    PRINT_TREE(prof, "RECONNECTION \n");
                    break;
                case TELNET_SUPPRESS_GO_AHEAD:
                    PRINT_TREE(prof, "SUPPRESS GO AHEAD \n");
                    break;
                case TELNET_APPROX_MESSAGE_SIZE_NEGOTIATION:
                    PRINT_TREE(prof, "APPROX MESSAGE SIZE NEGOTIATION \n");
                    break;
                case TELNET_STATUS:
                    PRINT_TREE(prof, "STATUS \n");
                    break;
                case TELNET_TIMING_MARK:
                    PRINT_TREE(prof, "TIMING MARK \n");
                    break;
                case TELNET_RCTE:
                    PRINT_TREE(prof, "REMOTE CONTROLLED TRANSMISSION AND ECHOING \n");
                    break;
                case TELNET_OLW:
                    PRINT_TREE(prof, "OUTPUT LINE WIDTH \n");
                    break;
                case TELNET_OPS:
                    PRINT_TREE(prof, "OUTPUT PAGE SIZE \n");
                    break;
                case TELNET_OCRD:
                    PRINT_TREE(prof, "OUTPUT CARRIAGE RETURN DISPOSITION \n");
                    break;
                case TELNET_OHTS:
                    PRINT_TREE(prof, "OUTPUT HORIZONTAL TAB STOPS \n");
                    break;
                case TELNET_OHTD:
                    PRINT_TREE(prof, "OUTPUT HORIZONTAL TAB DISPOSITION \n");
                    break;
                case TELNET_OFD:
                    PRINT_TREE(prof, "OUTPUT FORMFEED DISPOSITION \n");
                    break;
                case TELNET_OVT:
                    PRINT_TREE(prof, "OUTPUT VERTICAL TABSTOPS \n");
                    break;
                case TELNET_OVTD:
                    PRINT_TREE(prof, "OUTPUT VERTICAL TAB DISPOSITION \n");
                    break;
                case TELNET_OLFD:
                    PRINT_TREE(prof, "OUTPUT LINEFEED DISPOSITION \n");
                    break;
                case TELNET_EXTEND_ASCII:
                    PRINT_TREE(prof, "EXTENDED ASCII \n");
                    break;
                case TELNET_LOGOUT:
                    PRINT_TREE(prof, "LOGOUT \n");
                    break;
                case TELNET_BYTE_MACRO:
                    PRINT_TREE(prof, "BYTE MACRO \n");
                    break;
                case TELNET_DATA_ENTRY_TERMINAL:
                    PRINT_TREE(prof, "DATA ENTRY TERMINAL \n");
                    break;  
                case TELNET_SUPDUP:
                    PRINT_TREE(prof, "SUPDUP \n");
                    break;
                case TELNET_SUPDUP_OUTPUT:
                    PRINT_TREE(prof, "SUPDUP OUTPUT \n");
                    break;
                case TELNET_SEND_LOCATION:
                    PRINT_TREE(prof, "SEND LOCATION \n");
                    break;
                case TELNET_TERMINAL_TYPE:
                    PRINT_TREE(prof, "TERMINAL TYPE \n");
                    break;
                case TELNET_END_OF_RECORD:
                    PRINT_TREE(prof, "END OF RECORD \n");
                    break;
                case TELNET_TUID:
                    PRINT_TREE(prof, "TUID \n");
                    break;
                case TELNET_OUTMRK:
                    PRINT_TREE(prof, "OUTPUT MARKING \n");
                    break;
                case TELNET_TTYLOC:
                    PRINT_TREE(prof, "TTYLOC \n");
                    break;
                case TELNET_3270_REGIME:
                    PRINT_TREE(prof, "3270 REGIME \n");
                    break;
                case TELNET_X3_PAD:
                    PRINT_TREE(prof, "X3 PAD \n");
                    break;
                case TELNET_NAWS:
                    PRINT_TREE(prof, "NAWS \n");
                    break;
                case TELNET_TERMINAL_SPEED:
                    PRINT_TREE(prof, "TERMINAL SPEED \n");
                    break;
                case TELNET_TOGGLE_FLOW_CONTROL:
                    PRINT_TREE(prof, "TOGGLE FLOW CONTROL \n");
                    break;
                case TELNET_LINEMODE:
                    PRINT_TREE(prof, "LINEMODE \n");
                    break;
                case TELNET_X_DISPLAY_LOCATION:
                    PRINT_TREE(prof, "X DISPLAY LOCATION \n");
                    break;
                case TELNET_OLD_ENVIRONMENT_VARIABLES:
                    PRINT_TREE(prof, "OLD ENVIRONMENT VARIABLES \n");
                    break;
                case TELNET_AUTHENTICATION:
                    PRINT_TREE(prof, "AUTHENTICATION \n");
                    break;
                case TELNET_ENCRYPTION:
                    PRINT_TREE(prof, "ENCRYPTION \n");
                    break;
                case TELNET_NEW_ENVIRONMENT_VARIABLES:
                    PRINT_TREE(prof, "NEW ENVIRONMENT VARIABLES \n");
                    break;
                case TELNET_TN3270E:
                    PRINT_TREE(prof, "TN3270E \n");
                    break;
                case TELNET_XAUTH:
                    PRINT_TREE(prof, "XAUTH \n");
                    break;
                case TELNET_CHARSET:
                    PRINT_TREE(prof, "CHARSET \n");
                    break;  
                case TELNET_REMOTE_SERIAL_PORT:
                    PRINT_TREE(prof, "REMOTE SERIAL PORT \n");
                    break;
                case TELNET_COM_PORT_CONTROL:
                    PRINT_TREE(prof, "COM PORT CONTROL \n");
                    break;
                case TELNET_SUPPRESS_LOCAL_ECHO:
                    PRINT_TREE(prof, "SUPPRESS LOCAL ECHO \n");
                    break;
                case TELNET_START_TLS:
                    PRINT_TREE(prof, "START TLS \n");
                    break;
                case TELNET_KERMIT:
                    PRINT_TREE(prof, "KERMIT \n");
                    break;
                case TELNET_SEND_URL:
                    PRINT_TREE(prof, "SEND URL \n");
                    break;
                case TELNET_FORWARD_X:
                    PRINT_TREE(prof, "FORWARD X \n");
                    break;
                case TELNET_PRAGMA_LOGON:
                    PRINT_TREE(prof, "PRAGMA LOGON \n");
                    break;
                case TELNET_SSPI_LOGON:
                    PRINT_TREE(prof, "SSPI LOGON \n");
                    break;
                case TELNET_PRAGMA_HEARTBEAT:
                    PRINT_TREE(prof, "PRAGMA HEARTBEAT \n");
                    break;
                case TELNET_EXOPL:
                    PRINT_TREE(prof, "EXOPL \n");
                    break;
                default:
                    PRINT_TREE(prof, "UNKNOWN \n");
                    break;
                }
                printf("\n");
            } else {
                print_content(prof, verbose, size, packet);
            }
        }
    }
}

void parse_pop3(const u_char *packet, int verbose, int prof, int size) {
    switch (verbose) {
    case 1:
    case 2:
    case 3:
        PRINT_NEW_STATE(prof, verbose, BGRN "POP" GRN);

        if(verbose == 1) break ; // No need to print the rest of the header
        
        print_content(prof, verbose, size, packet);
    }
}   