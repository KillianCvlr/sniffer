#include "protocols/arp.h"

void parse_arp(const u_char *packet, int verbose, int prof) {
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