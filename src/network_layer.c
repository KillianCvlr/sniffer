#include "tools.h"          // Path: include/tools.h
#include "headers.h"        // Path: include/headers.h
#include "network_layer.h"   // Path: include/network_layer.h

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
        printf("ok");
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