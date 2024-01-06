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

        PRINT_TREE(prof, BBLU "IP version :" BLU" %i\n", ip->ip_v);
        PRINT_TREE(prof, BBLU "IP header length :" BLU" %i (%i bytes)\n", 
                                    ip->ip_hl, ip->ip_hl * 4);
        PRINT_TREE(prof, BBLU "Type of Service :" BLU" %i\n", ip->ip_tos);
        PRINT_TREE(prof, BBLU "Total length :" BLU" %u\n", ntohs(ip->ip_len));
        PRINT_TREE(prof, BBLU "Transaction id :" BLU" 0x%.2x\n",
                                    ntohs(ip->ip_id));
        PRINT_TREE(prof, BBLU "Fragment offset field :" BLU" 0x%.2x\n", 
                                    ntohs(ip->ip_off));
        PRINT_TREE(prof, BBLU "Checksum  :" BLU" 0x%x\n", ntohs(ip->ip_sum));
        PRINT_TREE(prof, BBLU "Time to lve :" BLU" %i\n", ip->ip_ttl);
        PRINT_TREE(prof, BBLU "Protocol :" BLU" %i\n", ip->ip_p);

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