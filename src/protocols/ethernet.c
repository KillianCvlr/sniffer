
#include "protocols/ethernet.h"

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
        parse_arp(packet + sizeof(struct ether_header), verbose, prof+1);
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
