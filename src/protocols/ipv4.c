#include "headers.h"

void parse_ipv4(const u_char *packet, int verbose, int prof) {
    struct ip *ip = (struct ip *)(packet);

    switch(verbose) {
    case 1:
    case 2:    
    case 3:
        PRINT_NEW_STATE(prof, verbose, BHBLU "IPV4" BLU);

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
        PRINT_NEW_STATE(prof+1, verbose, "ICMPv6");
        break;
    }
}